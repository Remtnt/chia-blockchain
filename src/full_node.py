import asyncio
import concurrent
import logging
import time
from asyncio import Event
from hashlib import sha256
from secrets import token_bytes
from typing import AsyncGenerator, List, Optional, Tuple, Dict

from blspy import PrivateKey, Signature

from chiapos import Verifier
from src.blockchain import Blockchain, ReceiveBlockResult
from src.consensus.constants import constants
from src.consensus.pot_iterations import calculate_iterations
from src.consensus.weight_verifier import verify_weight
from src.store import FullNodeStore
from src.protocols import farmer_protocol, peer_protocol, timelord_protocol
from src.server.outbound_message import Delivery, Message, NodeType, OutboundMessage
from src.server.server import ChiaServer
from src.types.body import Body
from src.types.challenge import Challenge
from src.types.fees_target import FeesTarget
from src.types.full_block import FullBlock
from src.types.header import Header, HeaderData
from src.types.header_block import HeaderBlock, SmallHeaderBlock
from src.types.peer_info import PeerInfo
from src.types.proof_of_space import ProofOfSpace
from src.types.sized_bytes import bytes32
from src.util import errors
from src.util.api_decorators import api_request
from src.util.errors import BlockNotInBlockchain, InvalidUnfinishedBlock
from src.util.ints import uint32, uint64

log = logging.getLogger(__name__)
OutboundMessageGenerator = AsyncGenerator[OutboundMessage, None]


class FullNode:
    def __init__(self, store: FullNodeStore, blockchain: Blockchain, config: Dict):
        self.store: FullNodeStore = store
        self.blockchain: Blockchain = blockchain
        self.config: Dict = config
        self._shut_down: bool = False  # Set to true to close all infinite loops
        self.server: Optional[ChiaServer] = None
        log.warning(f"{self.config}")

    def _set_server(self, server: ChiaServer):
        self.server = server

    async def _send_tips_to_farmers(
        self, delivery: Delivery = Delivery.BROADCAST
    ) -> OutboundMessageGenerator:
        """
        Sends all of the current heads to all farmer peers. Also sends the latest
        estimated proof of time rate, so farmer can calulate which proofs are good.
        """
        requests: List[farmer_protocol.ProofOfSpaceFinalized] = []
        async with self.store.lock:
            tips_raw = self.blockchain.get_current_tips()
            tips = await self.store.get_header_blocks_by_hash(
                [t.header_hash for t in tips_raw]
            )
            for tip in tips:
                assert tip.proof_of_time and tip.challenge
                challenge_hash = tip.challenge.get_hash()
                height = tip.challenge.height
                quality = tip.proof_of_space.verify_and_get_quality()
                if tip.height > 0:
                    difficulty: uint64 = self.blockchain.get_next_difficulty(
                        tip.prev_header_hash
                    )
                else:
                    difficulty = tip.weight
                requests.append(
                    farmer_protocol.ProofOfSpaceFinalized(
                        challenge_hash, height, tip.weight, quality, difficulty
                    )
                )
            proof_of_time_rate: uint64 = self.blockchain.get_next_ips(tips[0])
        rate_update = farmer_protocol.ProofOfTimeRate(proof_of_time_rate)
        yield OutboundMessage(
            NodeType.FARMER, Message("proof_of_time_rate", rate_update), delivery
        )
        for request in requests:
            yield OutboundMessage(
                NodeType.FARMER, Message("proof_of_space_finalized", request), delivery
            )

    async def _send_challenges_to_timelords(
        self, delivery: Delivery = Delivery.BROADCAST
    ) -> OutboundMessageGenerator:
        """
        Sends all of the current heads (as well as Pos infos) to all timelord peers.
        """
        challenge_requests: List[timelord_protocol.ChallengeStart] = []
        pos_info_requests: List[timelord_protocol.ProofOfSpaceInfo] = []
        tips: List[SmallHeaderBlock] = self.blockchain.get_current_tips()
        for tip in tips:
            assert tip.challenge
            challenge_hash = tip.challenge.get_hash()
            challenge_requests.append(
                timelord_protocol.ChallengeStart(
                    challenge_hash, tip.challenge.total_weight
                )
            )

        tip_hashes = [tip.header_hash for tip in tips]
        tip_infos = [
            tup[0]
            for tup in list((self.store.get_unfinished_blocks()).items())
            if tup[1].prev_header_hash in tip_hashes
        ]
        for chall, iters in tip_infos:
            pos_info_requests.append(timelord_protocol.ProofOfSpaceInfo(chall, iters))
        for challenge_msg in challenge_requests:
            yield OutboundMessage(
                NodeType.TIMELORD, Message("challenge_start", challenge_msg), delivery
            )
        for pos_info_msg in pos_info_requests:
            yield OutboundMessage(
                NodeType.TIMELORD,
                Message("proof_of_space_info", pos_info_msg),
                delivery,
            )

    async def _on_connect(self) -> OutboundMessageGenerator:
        """
        Whenever we connect to another node, send them our current heads. Also send heads to farmers
        and challenges to timelords.
        """
        blocks: List[FullBlock] = []

        tips: List[SmallHeaderBlock] = self.blockchain.get_current_tips()
        for t in tips:
            block = await self.store.get_block(t.header.get_hash())
            assert block
            blocks.append(block)
        for block in blocks:
            request = peer_protocol.Block(block)
            yield OutboundMessage(
                NodeType.FULL_NODE, Message("block", request), Delivery.RESPOND
            )

        # Update farmers and timelord with most recent information
        async for msg in self._send_challenges_to_timelords(Delivery.RESPOND):
            yield msg
        async for msg in self._send_tips_to_farmers(Delivery.RESPOND):
            yield msg

    def _num_needed_peers(self) -> int:
        assert self.server is not None
        diff = self.config["target_peer_count"] - len(
            self.server.global_connections.get_full_node_connections()
        )
        return diff if diff >= 0 else 0

    def _start_bg_tasks(self):
        """
        Start a background task connecting periodically to the introducer and
        requesting the peer list.
        """
        introducer = self.config["introducer_peer"]
        introducer_peerinfo = PeerInfo(introducer["host"], introducer["port"])

        async def introducer_client():
            async def on_connect() -> OutboundMessageGenerator:
                msg = Message("request_peers", peer_protocol.RequestPeers())
                yield OutboundMessage(NodeType.INTRODUCER, msg, Delivery.RESPOND)

            while not self._shut_down:
                # The first time connecting to introducer, keep trying to connect
                if self._num_needed_peers():
                    if not await self.server.start_client(
                        introducer_peerinfo, on_connect
                    ):
                        await asyncio.sleep(5)
                        continue
                await asyncio.sleep(self.config["introducer_connect_interval"])

        asyncio.create_task(introducer_client())

    def _shutdown(self):
        self._shut_down = True

    async def _sync(self) -> OutboundMessageGenerator:
        """
        Performs a full sync of the blockchain.
            - Check which are the heaviest tips
            - Request headers for the heaviest
            - Verify the weight of the tip, using the headers
            - Find the fork point to see where to start downloading blocks
            - Blacklist peers that provide invalid blocks
            - Sync blockchain up to heads (request blocks in batches)
        """
        log.info("Starting to perform sync with peers.")
        log.info("Waiting to receive tips from peers.")
        # TODO: better way to tell that we have finished receiving tips
        await asyncio.sleep(5)
        highest_weight: uint64 = uint64(0)
        tip_block: FullBlock
        tip_height = 0
        sync_start_time = time.time()

        # Based on responses from peers about the current heads, see which head is the heaviest
        # (similar to longest chain rule).

        potential_tips: List[
            Tuple[bytes32, FullBlock]
        ] = self.store.get_potential_tips_tuples()
        log.info(f"Have collected {len(potential_tips)} potential tips")
        for header_hash, potential_tip_block in potential_tips:
            if potential_tip_block.header_block.challenge is None:
                raise ValueError(
                    f"Invalid tip block {potential_tip_block.header_hash} received"
                )
            if potential_tip_block.header_block.challenge.total_weight > highest_weight:
                highest_weight = potential_tip_block.header_block.challenge.total_weight
                tip_block = potential_tip_block
                tip_height = potential_tip_block.header_block.challenge.height
        if highest_weight <= max(
            [t.weight for t in self.blockchain.get_current_tips()]
        ):
            log.info("Not performing sync, already caught up.")
            return

        assert tip_block
        log.info(f"Tip block {tip_block.header_hash} tip height {tip_block.height}")

        for height in range(0, tip_block.height + 1):
            self.store.set_potential_headers_received(uint32(height), Event())
            self.store.set_potential_blocks_received(uint32(height), Event())
            self.store.set_potential_hashes_received(Event())

        timeout = 200
        sleep_interval = 10
        total_time_slept = 0

        while True:
            if total_time_slept > timeout:
                raise TimeoutError("Took too long to fetch header hashes.")
            if self._shut_down:
                return
            # Download all the header hashes and find the fork point
            request = peer_protocol.RequestAllHeaderHashes(tip_block.header_hash)
            yield OutboundMessage(
                NodeType.FULL_NODE,
                Message("request_all_header_hashes", request),
                Delivery.RANDOM,
            )
            try:
                phr = self.store.get_potential_hashes_received()
                assert phr is not None
                await asyncio.wait_for(
                    phr.wait(), timeout=sleep_interval,
                )
                break
            except concurrent.futures.TimeoutError:
                total_time_slept += sleep_interval
                log.warning("Did not receive desired header hashes")

        # Finding the fork point allows us to only download headers and blocks from the fork point
        header_hashes = self.store.get_potential_hashes()
        fork_point_height: uint32 = self.blockchain.find_fork_point(header_hashes)
        fork_point_hash: bytes32 = header_hashes[fork_point_height]
        log.info(f"Fork point: {fork_point_hash} at height {fork_point_height}")

        # Now, we download all of the headers in order to verify the weight, in batches
        headers: List[HeaderBlock] = []

        # Download headers in batches. We download a few batches ahead in case there are delays or peers
        # that don't have the headers that we need.
        last_request_time: float = 0
        highest_height_requested: uint32 = uint32(0)
        request_made: bool = False
        for height_checkpoint in range(
            fork_point_height + 1, tip_height + 1, self.config["max_headers_to_send"]
        ):
            end_height = min(
                height_checkpoint + self.config["max_headers_to_send"], tip_height + 1
            )

            total_time_slept = 0
            while True:
                if self._shut_down:
                    return
                if total_time_slept > timeout:
                    raise TimeoutError("Took too long to fetch blocks")

                # Request batches that we don't have yet
                for batch in range(0, self.config["num_sync_batches"]):
                    batch_start = (
                        height_checkpoint + batch * self.config["max_headers_to_send"]
                    )
                    batch_end = min(
                        batch_start + self.config["max_headers_to_send"], tip_height + 1
                    )

                    if batch_start > tip_height:
                        # We have asked for all blocks
                        break

                    blocks_missing = any(
                        [
                            not (
                                self.store.get_potential_headers_received(uint32(h))
                            ).is_set()
                            for h in range(batch_start, batch_end)
                        ]
                    )
                    if (
                        time.time() - last_request_time > sleep_interval
                        and blocks_missing
                    ) or (batch_end - 1) > highest_height_requested:
                        # If we are missing header blocks in this batch, and we haven't made a request in a while,
                        # Make a request for this batch. Also, if we have never requested this batch, make
                        # the request
                        if batch_end - 1 > highest_height_requested:
                            highest_height_requested = batch_end - 1

                        request_made = True
                        request_hb = peer_protocol.RequestHeaderBlocks(
                            tip_block.header_block.header.get_hash(),
                            [uint32(h) for h in range(batch_start, batch_end)],
                        )
                        log.info(f"Requesting header blocks {batch_start, batch_end}.")
                        yield OutboundMessage(
                            NodeType.FULL_NODE,
                            Message("request_header_blocks", request_hb),
                            Delivery.RANDOM,
                        )
                if request_made:
                    # Reset the timer for requests, so we don't overload other peers with requests
                    last_request_time = time.time()
                    request_made = False

                # Wait for the first batch (the next "max_blocks_to_send" blocks to arrive)
                awaitables = [
                    (self.store.get_potential_headers_received(uint32(height))).wait()
                    for height in range(height_checkpoint, end_height)
                ]
                future = asyncio.gather(*awaitables, return_exceptions=True)
                try:
                    await asyncio.wait_for(future, timeout=sleep_interval)
                    break
                except concurrent.futures.TimeoutError:
                    try:
                        await future
                    except asyncio.CancelledError:
                        pass
                    total_time_slept += sleep_interval
                    log.info(f"Did not receive desired header blocks")

        for h in range(fork_point_height + 1, tip_height + 1):
            header = self.store.get_potential_header(uint32(h))
            assert header is not None
            headers.append(header)

        log.info(f"Downloaded headers up to tip height: {tip_height}")
        if not verify_weight(
            tip_block.header_block, headers, self.blockchain.headers[fork_point_hash],
        ):
            raise errors.InvalidWeight(
                f"Weight of {tip_block.header_block.header.get_hash()} not valid."
            )

        log.info(
            f"Validated weight of headers. Downloaded {len(headers)} headers, tip height {tip_height}"
        )
        assert tip_height == fork_point_height + len(headers)
        self.store.clear_potential_headers()
        headers.clear()

        # Download blocks in batches, and verify them as they come in. We download a few batches ahead,
        # in case there are delays.
        last_request_time = 0
        highest_height_requested = uint32(0)
        request_made = False
        for height_checkpoint in range(
            fork_point_height + 1, tip_height + 1, self.config["max_blocks_to_send"]
        ):
            end_height = min(
                height_checkpoint + self.config["max_blocks_to_send"], tip_height + 1
            )

            total_time_slept = 0
            while True:
                if self._shut_down:
                    return
                if total_time_slept > timeout:
                    raise TimeoutError("Took too long to fetch blocks")

                # Request batches that we don't have yet
                for batch in range(0, self.config["num_sync_batches"]):
                    batch_start = (
                        height_checkpoint + batch * self.config["max_blocks_to_send"]
                    )
                    batch_end = min(
                        batch_start + self.config["max_blocks_to_send"], tip_height + 1
                    )

                    if batch_start > tip_height:
                        # We have asked for all blocks
                        break

                    blocks_missing = any(
                        [
                            not (
                                self.store.get_potential_blocks_received(uint32(h))
                            ).is_set()
                            for h in range(batch_start, batch_end)
                        ]
                    )
                    if (
                        time.time() - last_request_time > sleep_interval
                        and blocks_missing
                    ) or (batch_end - 1) > highest_height_requested:
                        # If we are missing blocks in this batch, and we haven't made a request in a while,
                        # Make a request for this batch. Also, if we have never requested this batch, make
                        # the request
                        log.info(
                            f"Requesting sync blocks {[i for i in range(batch_start, batch_end)]}"
                        )
                        if batch_end - 1 > highest_height_requested:
                            highest_height_requested = batch_end - 1
                        request_made = True
                        request_sync = peer_protocol.RequestSyncBlocks(
                            tip_block.header_block.header.header_hash,
                            [
                                uint32(height)
                                for height in range(batch_start, batch_end)
                            ],
                        )
                        yield OutboundMessage(
                            NodeType.FULL_NODE,
                            Message("request_sync_blocks", request_sync),
                            Delivery.RANDOM,
                        )
                if request_made:
                    # Reset the timer for requests, so we don't overload other peers with requests
                    last_request_time = time.time()
                    request_made = False

                # Wait for the first batch (the next "max_blocks_to_send" blocks to arrive)
                awaitables = [
                    (self.store.get_potential_blocks_received(uint32(height))).wait()
                    for height in range(height_checkpoint, end_height)
                ]
                future = asyncio.gather(*awaitables, return_exceptions=True)
                try:
                    await asyncio.wait_for(future, timeout=sleep_interval)
                    break
                except concurrent.futures.TimeoutError:
                    try:
                        await future
                    except asyncio.CancelledError:
                        pass
                    total_time_slept += sleep_interval
                    log.info("Did not receive desired blocks")

            # Verifies this batch, which we are guaranteed to have (since we broke from the above loop)
            blocks = []
            for height in range(height_checkpoint, end_height):
                b: Optional[FullBlock] = await self.store.get_potential_block(
                    uint32(height)
                )
                assert b is not None
                blocks.append(b)

            validation_start_time = time.time()
            prevalidate_results = await self.blockchain.pre_validate_blocks(blocks)
            index = 0
            for height in range(height_checkpoint, end_height):
                if self._shut_down:
                    return
                block: Optional[FullBlock] = await self.store.get_potential_block(
                    uint32(height)
                )
                assert block is not None

                prev_block: Optional[FullBlock] = await self.store.get_potential_block(
                    uint32(height - 1)
                )
                if prev_block is None:
                    prev_block = await self.store.get_block(block.prev_header_hash)
                assert prev_block is not None

                # The block gets permanantly added to the blockchain
                validated, pos = prevalidate_results[index]
                index += 1

                async with self.store.lock:
                    result = await self.blockchain.receive_block(
                        block, prev_block.header_block, validated, pos
                    )
                    if (
                        result == ReceiveBlockResult.INVALID_BLOCK
                        or result == ReceiveBlockResult.DISCONNECTED_BLOCK
                    ):
                        raise RuntimeError(f"Invalid block {block.header_hash}")

                    # Always immediately add the block to the database, after updating blockchain state
                    await self.store.add_block(block)

                assert (
                    max([h.height for h in self.blockchain.get_current_tips()])
                    >= height
                )
                self.store.set_proof_of_time_estimate_ips(
                    self.blockchain.get_next_ips(block.header_block)
                )
            log.info(
                f"Took {time.time() - validation_start_time} seconds to validate and add blocks "
                f"{height_checkpoint} to {end_height}."
            )
        assert max([h.height for h in self.blockchain.get_current_tips()]) == tip_height
        log.info(
            f"Finished sync up to height {tip_height}. Total time: "
            f"{round((time.time() - sync_start_time)/60, 2)} minutes."
        )

    async def _finish_sync(self) -> OutboundMessageGenerator:
        """
        Finalize sync by setting sync mode to False, clearing all sync information, and adding any final
        blocks that we have finalized recently.
        """
        potential_fut_blocks = (self.store.get_potential_future_blocks()).copy()
        self.store.set_sync_mode(False)

        async with self.store.lock:
            await self.store.clear_sync_info()

        for block in potential_fut_blocks:
            if self._shut_down:
                return
            async for msg in self.block(peer_protocol.Block(block)):
                yield msg

        # Update farmers and timelord with most recent information
        async for msg in self._send_challenges_to_timelords():
            yield msg
        async for msg in self._send_tips_to_farmers():
            yield msg

    @api_request
    async def request_all_header_hashes(
        self, request: peer_protocol.RequestAllHeaderHashes
    ) -> OutboundMessageGenerator:
        try:
            header_hashes = self.blockchain.get_header_hashes(request.tip_header_hash)
            message = Message(
                "all_header_hashes", peer_protocol.AllHeaderHashes(header_hashes)
            )
            yield OutboundMessage(NodeType.FULL_NODE, message, Delivery.RESPOND)
        except ValueError:
            log.info("Do not have requested header hashes.")

    @api_request
    async def all_header_hashes(
        self, all_header_hashes: peer_protocol.AllHeaderHashes
    ) -> OutboundMessageGenerator:
        assert len(all_header_hashes.header_hashes) > 0
        self.store.set_potential_hashes(all_header_hashes.header_hashes)
        phr = self.store.get_potential_hashes_received()
        assert phr is not None
        phr.set()
        for _ in []:  # Yields nothing
            yield _

    @api_request
    async def request_header_blocks(
        self, request: peer_protocol.RequestHeaderBlocks
    ) -> OutboundMessageGenerator:
        """
        A peer requests a list of header blocks, by height. Used for syncing or light clients.
        """
        start = time.time()
        if len(request.heights) > self.config["max_headers_to_send"]:
            raise errors.TooManyheadersRequested(
                f"The max number of headers is {self.config['max_headers_to_send']},\
                                                but requested {len(request.heights)}"
            )

        try:
            header_hashes: List[
                HeaderBlock
            ] = self.blockchain.get_header_hashes_by_height(
                request.heights, request.tip_header_hash
            )
            header_blocks: List[
                HeaderBlock
            ] = await self.store.get_header_blocks_by_hash(header_hashes)
            log.info(f"Got header blocks by height {time.time() - start}")
        except KeyError:
            return
        except BlockNotInBlockchain as e:
            log.info(f"{e}")
            return

        response = peer_protocol.HeaderBlocks(request.tip_header_hash, header_blocks)
        yield OutboundMessage(
            NodeType.FULL_NODE, Message("header_blocks", response), Delivery.RESPOND
        )

    @api_request
    async def header_blocks(
        self, request: peer_protocol.HeaderBlocks
    ) -> OutboundMessageGenerator:
        """
        Receive header blocks from a peer.
        """
        log.info(
            f"Received header blocks {request.header_blocks[0].height, request.header_blocks[-1].height}."
        )
        for header_block in request.header_blocks:
            self.store.add_potential_header(header_block)
            (self.store.get_potential_headers_received(header_block.height)).set()

        for _ in []:  # Yields nothing
            yield _

    @api_request
    async def request_sync_blocks(
        self, request: peer_protocol.RequestSyncBlocks
    ) -> OutboundMessageGenerator:
        """
        Responsd to a peers request for syncing blocks.
        """
        blocks: List[FullBlock] = []
        async with self.store.lock:
            tip_block: Optional[FullBlock] = await self.store.get_block(
                request.tip_header_hash
            )
        if tip_block is not None:
            if len(request.heights) > self.config["max_blocks_to_send"]:
                raise errors.TooManyheadersRequested(
                    f"The max number of blocks is "
                    f"{self.config['max_blocks_to_send']},"
                    f"but requested {len(request.heights)}"
                )
            try:
                header_hashes: List[
                    HeaderBlock
                ] = self.blockchain.get_header_hashes_by_height(
                    request.heights, request.tip_header_hash
                )
                header_blocks: List[
                    HeaderBlock
                ] = await self.store.get_header_blocks_by_hash(header_hashes)
                for header_block in header_blocks:
                    fetched = await self.store.get_block(header_block.header.get_hash())
                    assert fetched
                    blocks.append(fetched)
            except KeyError:
                log.info("Do not have required blocks")
                return
            except BlockNotInBlockchain as e:
                log.info(f"{e}")
                return
        else:
            # We don't have the blocks that the client is looking for
            log.info(f"Peer requested tip {request.tip_header_hash} that we don't have")
            return
        response = Message(
            "sync_blocks", peer_protocol.SyncBlocks(request.tip_header_hash, blocks)
        )
        yield OutboundMessage(NodeType.FULL_NODE, response, Delivery.RESPOND)

    @api_request
    async def sync_blocks(
        self, request: peer_protocol.SyncBlocks
    ) -> OutboundMessageGenerator:
        """
        We have received the blocks that we needed for syncing. Add them to processing queue.
        """
        log.info(f"Received sync blocks {[b.height for b in request.blocks]}")

        if not self.store.get_sync_mode():
            log.warning("Receiving sync blocks when we are not in sync mode.")
            return

        for block in request.blocks:
            await self.store.add_potential_block(block)
            if (
                not self.store.get_sync_mode()
            ):  # We might have left sync mode after the previous await
                return
            (self.store.get_potential_blocks_received(block.height)).set()

        for _ in []:  # Yields nothing
            yield _

    @api_request
    async def request_header_hash(
        self, request: farmer_protocol.RequestHeaderHash
    ) -> OutboundMessageGenerator:
        """
        Creates a block body and header, with the proof of space, coinbase, and fee targets provided
        by the farmer, and sends the hash of the header data back to the farmer.
        """
        plot_seed: bytes32 = request.proof_of_space.get_plot_seed()

        # Checks that the proof of space is valid
        quality_string: bytes = Verifier().validate_proof(
            plot_seed,
            request.proof_of_space.size,
            request.challenge_hash,
            bytes(request.proof_of_space.proof),
        )
        assert quality_string

        # Retrieves the correct head for the challenge
        tips: List[SmallHeaderBlock] = self.blockchain.get_current_tips()
        target_tip: Optional[SmallHeaderBlock] = None
        for tip in tips:
            assert tip.challenge
            if tip.challenge.get_hash() == request.challenge_hash:
                target_tip = tip
        if target_tip is None:
            # TODO: should we still allow the farmer to farm?
            log.warning(
                f"Challenge hash: {request.challenge_hash} not in one of three heads"
            )
            return

        # TODO: use mempool to grab best transactions, for the selected head
        transactions_generator: bytes32 = sha256(b"").digest()
        # TODO: calculate the fees of these transactions
        fees: FeesTarget = FeesTarget(request.fees_target_puzzle_hash, uint64(0))
        aggregate_sig: Signature = PrivateKey.from_seed(b"12345").sign(b"anything")
        # TODO: calculate aggregate signature based on transactions
        # TODO: calculate cost of all transactions
        cost = uint64(0)

        # Creates a block with transactions, coinbase, and fees
        body: Body = Body(
            request.coinbase,
            request.coinbase_signature,
            fees,
            aggregate_sig,
            transactions_generator,
            cost,
        )

        # Creates the block header
        prev_header_hash: bytes32 = target_tip.header.get_hash()
        timestamp: uint64 = uint64(int(time.time()))

        # TODO: use a real BIP158 filter based on transactions
        filter_hash: bytes32 = token_bytes(32)
        proof_of_space_hash: bytes32 = request.proof_of_space.get_hash()
        body_hash: Body = body.get_hash()
        extension_data: bytes32 = bytes32([0] * 32)
        block_header_data: HeaderData = HeaderData(
            prev_header_hash,
            timestamp,
            filter_hash,
            proof_of_space_hash,
            body_hash,
            extension_data,
        )

        block_header_data_hash: bytes32 = block_header_data.get_hash()

        # self.stores this block so we can submit it to the blockchain after it's signed by harvester
        self.store.add_candidate_block(
            proof_of_space_hash, body, block_header_data, request.proof_of_space
        )

        message = farmer_protocol.HeaderHash(
            proof_of_space_hash, block_header_data_hash
        )
        yield OutboundMessage(
            NodeType.FARMER, Message("header_hash", message), Delivery.RESPOND
        )

    @api_request
    async def header_signature(
        self, header_signature: farmer_protocol.HeaderSignature
    ) -> OutboundMessageGenerator:
        """
        Signature of header hash, by the harvester. This is enough to create an unfinished
        block, which only needs a Proof of Time to be finished. If the signature is valid,
        we call the unfinished_block routine.
        """
        candidate: Optional[
            Tuple[Body, HeaderData, ProofOfSpace]
        ] = self.store.get_candidate_block(header_signature.pos_hash)
        if candidate is None:
            log.warning(f"PoS hash {header_signature.pos_hash} not found in database")
            return
        # Verifies that we have the correct header and body self.stored
        block_body, block_header_data, pos = candidate

        assert block_header_data.get_hash() == header_signature.header_hash

        block_header: Header = Header(
            block_header_data, header_signature.header_signature
        )
        header: HeaderBlock = HeaderBlock(pos, None, None, block_header)
        unfinished_block_obj: FullBlock = FullBlock(header, block_body)

        # Propagate to ourselves (which validates and does further propagations)
        request = peer_protocol.UnfinishedBlock(unfinished_block_obj)
        async for m in self.unfinished_block(request):
            # Yield all new messages (propagation to peers)
            yield m

    # TIMELORD PROTOCOL
    @api_request
    async def proof_of_time_finished(
        self, request: timelord_protocol.ProofOfTimeFinished
    ) -> OutboundMessageGenerator:
        """
        A proof of time, received by a peer timelord. We can use this to complete a block,
        and call the block routine (which handles propagation and verification of blocks).
        """
        dict_key = (
            request.proof.challenge_hash,
            request.proof.number_of_iterations,
        )

        unfinished_block_obj: Optional[FullBlock] = self.store.get_unfinished_block(
            dict_key
        )
        if not unfinished_block_obj:
            log.warning(
                f"Received a proof of time that we cannot use to complete a block {dict_key}"
            )
            return
        prev_full_block = await self.store.get_block(
            unfinished_block_obj.prev_header_hash
        )
        assert prev_full_block
        prev_block: HeaderBlock = prev_full_block.header_block
        difficulty: uint64 = self.blockchain.get_next_difficulty(
            unfinished_block_obj.prev_header_hash
        )
        assert prev_block.challenge

        challenge: Challenge = Challenge(
            request.proof.challenge_hash,
            unfinished_block_obj.header_block.proof_of_space.get_hash(),
            request.proof.output.get_hash(),
            uint32(prev_block.challenge.height + 1),
            uint64(prev_block.challenge.total_weight + difficulty),
            uint64(
                prev_block.challenge.total_iters + request.proof.number_of_iterations
            ),
        )

        new_header_block = HeaderBlock(
            unfinished_block_obj.header_block.proof_of_space,
            request.proof,
            challenge,
            unfinished_block_obj.header_block.header,
        )
        new_full_block: FullBlock = FullBlock(
            new_header_block, unfinished_block_obj.body
        )

        if self.store.get_sync_mode():
            self.store.add_potential_future_block(new_full_block)
        else:
            async for msg in self.block(peer_protocol.Block(new_full_block)):
                yield msg

    # PEER PROTOCOL
    @api_request
    async def new_proof_of_time(
        self, new_proof_of_time: peer_protocol.NewProofOfTime
    ) -> OutboundMessageGenerator:
        """
        A proof of time, received by a peer full node. If we have the rest of the block,
        we can complete it. Otherwise, we just verify and propagate the proof.
        """
        finish_block: bool = False
        propagate_proof: bool = False
        if self.store.get_unfinished_block(
            (
                new_proof_of_time.proof.challenge_hash,
                new_proof_of_time.proof.number_of_iterations,
            )
        ):

            finish_block = True
        elif new_proof_of_time.proof.is_valid(constants["DISCRIMINANT_SIZE_BITS"]):
            propagate_proof = True

        if finish_block:
            request = timelord_protocol.ProofOfTimeFinished(new_proof_of_time.proof)
            async for msg in self.proof_of_time_finished(request):
                yield msg
        if propagate_proof:
            yield OutboundMessage(
                NodeType.FULL_NODE,
                Message("new_proof_of_time", new_proof_of_time),
                Delivery.BROADCAST_TO_OTHERS,
            )

    @api_request
    async def unfinished_block(
        self, unfinished_block: peer_protocol.UnfinishedBlock
    ) -> OutboundMessageGenerator:
        """
        We have received an unfinished block, either created by us, or from another peer.
        We can validate it and if it's a good block, propagate it to other peers and
        timelords.
        """
        # Adds the unfinished block to seen, and check if it's seen before
        if self.store.seen_unfinished_block(unfinished_block.block.header_hash):
            return

        if not self.blockchain.is_child_of_head(unfinished_block.block):
            return

        if not await self.blockchain.validate_unfinished_block(unfinished_block.block):
            raise InvalidUnfinishedBlock()

        prev_full_block: Optional[FullBlock] = await self.store.get_block(
            unfinished_block.block.prev_header_hash
        )

        assert prev_full_block

        prev_block: HeaderBlock = prev_full_block.header_block

        assert prev_block.challenge

        challenge_hash: bytes32 = prev_block.challenge.get_hash()
        difficulty: uint64 = self.blockchain.get_next_difficulty(
            unfinished_block.block.header_block.prev_header_hash
        )
        vdf_ips: uint64 = self.blockchain.get_next_ips(prev_block)

        iterations_needed: uint64 = calculate_iterations(
            unfinished_block.block.header_block.proof_of_space,
            difficulty,
            vdf_ips,
            constants["MIN_BLOCK_TIME"],
        )

        if (
            self.store.get_unfinished_block((challenge_hash, iterations_needed))
            is not None
        ):
            return

        expected_time: uint64 = uint64(
            int(iterations_needed / (self.store.get_proof_of_time_estimate_ips()))
        )

        if expected_time > constants["PROPAGATION_DELAY_THRESHOLD"]:
            log.info(f"Block is slow, expected {expected_time} seconds, waiting")
            # If this block is slow, sleep to allow faster blocks to come out first
            await asyncio.sleep(5)

        leader: Tuple[uint32, uint64] = self.store.get_unfinished_block_leader()
        if leader is None or unfinished_block.block.height > leader[0]:
            log.info(
                f"This is the first unfinished block at height {unfinished_block.block.height}, so propagate."
            )
            # If this is the first block we see at this height, propagate
            self.store.set_unfinished_block_leader(
                (unfinished_block.block.height, expected_time)
            )
        elif unfinished_block.block.height == leader[0]:
            if expected_time > leader[1] + constants["PROPAGATION_THRESHOLD"]:
                # If VDF is expected to finish X seconds later than the best, don't propagate
                log.info(
                    f"VDF will finish too late {expected_time} seconds, so don't propagate"
                )
                return
            elif expected_time < leader[1]:
                log.info(
                    f"New best unfinished block at height {unfinished_block.block.height}"
                )
                # If this will be the first block to finalize, update our leader
                self.store.set_unfinished_block_leader((leader[0], expected_time))
        else:
            # If we have seen an unfinished block at a greater or equal height, don't propagate
            log.info(f"Unfinished block at old height, so don't propagate")
            return

        self.store.add_unfinished_block(
            (challenge_hash, iterations_needed), unfinished_block.block
        )

        timelord_request = timelord_protocol.ProofOfSpaceInfo(
            challenge_hash, iterations_needed
        )

        yield OutboundMessage(
            NodeType.TIMELORD,
            Message("proof_of_space_info", timelord_request),
            Delivery.BROADCAST,
        )
        yield OutboundMessage(
            NodeType.FULL_NODE,
            Message("unfinished_block", unfinished_block),
            Delivery.BROADCAST_TO_OTHERS,
        )

    @api_request
    async def block(self, block: peer_protocol.Block) -> OutboundMessageGenerator:
        """
        Receive a full block from a peer full node (or ourselves).
        """
        header_hash = block.block.header_block.header.get_hash()

        # Adds the block to seen, and check if it's seen before
        if self.blockchain.cointains_block(header_hash):
            return

        if self.store.get_sync_mode():
            # Add the block to our potential tips list
            self.store.add_potential_tip(block.block)
            return

        prevalidate_block = await self.blockchain.pre_validate_blocks([block.block])
        val, pos = prevalidate_block[0]

        async with self.store.lock:
            prev_block: Optional[FullBlock] = await self.store.get_block(
                block.block.prev_header_hash
            )

            added: ReceiveBlockResult
            if prev_block is None:
                added = ReceiveBlockResult.DISCONNECTED_BLOCK
            else:
                # Tries to add the block to the blockchain
                added = await self.blockchain.receive_block(
                    block.block, prev_block.header_block, val, pos
                )

            # Always immediately add the block to the database, after updating blockchain state
            if (
                added == ReceiveBlockResult.ADDED_AS_ORPHAN
                or added == ReceiveBlockResult.ADDED_TO_HEAD
            ):
                await self.store.add_block(block.block)

        if added == ReceiveBlockResult.ALREADY_HAVE_BLOCK:
            return
        elif added == ReceiveBlockResult.INVALID_BLOCK:
            log.warning(
                f"Block {header_hash} at height {block.block.height} is invalid."
            )
            return
        elif added == ReceiveBlockResult.DISCONNECTED_BLOCK:
            log.warning(f"Disconnected block {header_hash}")
            tip_height = min(
                [head.height for head in self.blockchain.get_current_tips()]
            )

            if (
                block.block.height
                > tip_height + self.config["sync_blocks_behind_threshold"]
            ):
                async with self.store.lock:
                    if self.store.get_sync_mode():
                        return
                    await self.store.clear_sync_info()
                    self.store.add_potential_tip(block.block)
                    self.store.set_sync_mode(True)
                log.info(
                    f"We are too far behind this block. Our height is {tip_height} and block is at "
                    f"{block.block.height}"
                )
                try:
                    # Performs sync, and catch exceptions so we don't close the connection
                    async for ret_msg in self._sync():
                        yield ret_msg
                except asyncio.CancelledError:
                    log.error("Syncing failed, CancelledError")
                except BaseException as e:
                    log.error(f"Error {type(e)}{e} with syncing")
                finally:
                    async for ret_msg in self._finish_sync():
                        yield ret_msg

            elif block.block.height >= tip_height - 3:
                log.info(
                    f"We have received a disconnected block at height {block.block.height}, current tip is {tip_height}"
                )
                msg = Message(
                    "request_block",
                    peer_protocol.RequestBlock(block.block.prev_header_hash),
                )
                self.store.add_disconnected_block(block.block)
                yield OutboundMessage(NodeType.FULL_NODE, msg, Delivery.RESPOND)
            return
        elif added == ReceiveBlockResult.ADDED_TO_HEAD:
            # Only propagate blocks which extend the blockchain (becomes one of the heads)
            log.info(
                f"Updated heads, new heights: {[b.height for b in self.blockchain.get_current_tips()]}"
            )

            difficulty = self.blockchain.get_next_difficulty(
                block.block.prev_header_hash
            )
            next_vdf_ips = self.blockchain.get_next_ips(block.block.header_block)
            log.info(f"Difficulty {difficulty} IPS {next_vdf_ips}")
            if next_vdf_ips != self.store.get_proof_of_time_estimate_ips():
                self.store.set_proof_of_time_estimate_ips(next_vdf_ips)
                rate_update = farmer_protocol.ProofOfTimeRate(next_vdf_ips)
                log.info(f"Sending proof of time rate {next_vdf_ips}")
                yield OutboundMessage(
                    NodeType.FARMER,
                    Message("proof_of_time_rate", rate_update),
                    Delivery.BROADCAST,
                )
                self.store.clear_seen_unfinished_blocks()

            assert block.block.header_block.proof_of_time
            assert block.block.header_block.challenge
            pos_quality = (
                block.block.header_block.proof_of_space.verify_and_get_quality()
            )

            farmer_request = farmer_protocol.ProofOfSpaceFinalized(
                block.block.header_block.challenge.get_hash(),
                block.block.height,
                block.block.weight,
                pos_quality,
                difficulty,
            )
            timelord_request = timelord_protocol.ChallengeStart(
                block.block.header_block.challenge.get_hash(),
                block.block.header_block.challenge.total_weight,
            )
            # Tell timelord to stop previous challenge and start with new one
            yield OutboundMessage(
                NodeType.TIMELORD,
                Message("challenge_start", timelord_request),
                Delivery.BROADCAST,
            )

            # Tell full nodes about the new block
            yield OutboundMessage(
                NodeType.FULL_NODE,
                Message("block", block),
                Delivery.BROADCAST_TO_OTHERS,
            )

            # Tell farmer about the new block
            yield OutboundMessage(
                NodeType.FARMER,
                Message("proof_of_space_finalized", farmer_request),
                Delivery.BROADCAST,
            )

        elif added == ReceiveBlockResult.ADDED_AS_ORPHAN:
            assert block.block.header_block.proof_of_time
            assert block.block.header_block.challenge
            log.info(
                f"Received orphan block of height {block.block.header_block.challenge.height}"
            )
        else:
            # Should never reach here, all the cases are covered
            assert False
            # Recursively process the next block if we have it

        # This code path is reached if added == ADDED_AS_ORPHAN or ADDED_TO_HEAD
        next_block: Optional[FullBlock] = self.store.get_disconnected_block_by_prev(
            block.block.header_hash
        )

        if next_block is not None:
            async for ret_msg in self.block(peer_protocol.Block(next_block)):
                yield ret_msg

        # Removes all temporary data for old blocks
        lowest_tip = min(tip.height for tip in self.blockchain.get_current_tips())
        clear_height = uint32(max(0, lowest_tip - 30))
        self.store.clear_candidate_blocks_below(clear_height)
        self.store.clear_unfinished_blocks_below(clear_height)
        self.store.clear_disconnected_blocks_below(clear_height)

    @api_request
    async def request_block(
        self, request_block: peer_protocol.RequestBlock
    ) -> OutboundMessageGenerator:
        block: Optional[FullBlock] = await self.store.get_block(
            request_block.header_hash
        )
        if block is not None:
            yield OutboundMessage(
                NodeType.FULL_NODE,
                Message("block", peer_protocol.Block(block)),
                Delivery.RESPOND,
            )

    @api_request
    async def peers(self, request: peer_protocol.Peers) -> OutboundMessageGenerator:
        if self.server is None:
            return
        conns = self.server.global_connections
        for peer in request.peer_list:
            conns.peers.add(peer)

        # Pseudo-message to close the connection
        yield OutboundMessage(NodeType.INTRODUCER, Message("", None), Delivery.CLOSE)

        unconnected = conns.get_unconnected_peers(
            recent_threshold=self.config["recent_peer_threshold"]
        )
        to_connect = unconnected[: self._num_needed_peers()]
        if not len(to_connect):
            return

        log.info(f"Trying to connect to peers: {to_connect}")
        tasks = []
        for peer in to_connect:
            tasks.append(asyncio.create_task(self.server.start_client(peer)))
        await asyncio.gather(*tasks)
