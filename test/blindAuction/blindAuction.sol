pragma solidity 0.4.25;

contract BlindAuction {
    struct Bid {
        bytes32 blindedBid;
        uint deposit;
    }
    uint public biddingEnd;
    uint public revealEnd;

    mapping(address => Bid[]) public bids;
    address public highestBidder;
    uint public highestBid;
    mapping(address => uint) pendingReturns;
    modifier onlyBefore(uint _time) {
        require(now < _time);
        _;
    }
    modifier onlyAfter(uint _time) {
        require(now > _time);
        _;
    }

    constructor(uint _biddingTime, uint _revealTime) public {
        biddingEnd = now + _biddingTime;
        revealEnd = biddingEnd + _revealTime;
    }

    function bid(bytes32 _blindedBid) public payable onlyBefore(biddingEnd) {
        bids[msg.sender].push(
            Bid({blindedBid: _blindedBid, deposit: msg.value})
        );
    }

    function reveal(
        uint[] values,
        bytes32[] secrets
    ) public onlyAfter(biddingEnd) onlyBefore(revealEnd) {
        require(values.length == secrets.length);
        for (
            uint i = 0;
            i < values.length && i < bids[msg.sender].length;
            i++
        ) {
            var bid_obj = bids[msg.sender][i];
            var (value, secret) = (values[i], secrets[i]);
            if (
                bid_obj.blindedBid == keccak256(value, secret) &&
                bid_obj.deposit >= value &&
                value > highestBid
            ) {
                highestBid = value;
                highestBidder = msg.sender;
            }
        }
    }

    function withdraw() public onlyAfter(revealEnd) {
        uint amount = pendingReturns[msg.sender];
        if (amount > 0) {
            if (msg.sender != highestBidder) msg.sender.transfer(amount);
            else msg.sender.transfer(amount - highestBid);
            pendingReturns[msg.sender] = 0;
        }
    }
}
