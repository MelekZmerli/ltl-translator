pragma solidity 0.4.25;

contract EtherGame {
    uint public payoutMileStone1 = 6 ether;
    uint public mileStone1Reward = 4 ether;
    uint public payoutMileStone2 = 10 ether;
    uint public mileStone2Reward = 6 ether;
    uint public finalMileStone = 20 ether;
    uint public finalReward = 10 ether;

    mapping(address => uint) redeemableEther;

    function play() public payable {
        require(msg.value == 1 ether);
        uint currentBalance = this.balance + msg.value;
        require(currentBalance <= finalMileStone);
        if (currentBalance == payoutMileStone1) {
            redeemableEther[msg.sender] += mileStone1Reward;
        } else if (currentBalance == payoutMileStone2) {
            redeemableEther[msg.sender] += mileStone2Reward;
        } else if (currentBalance == finalMileStone) {
            redeemableEther[msg.sender] += finalReward;
        }
        return;
    }

    function claimReward() public {
        require(this.balance == finalMileStone);
        require(redeemableEther[msg.sender] > 0);
        redeemableEther[msg.sender] = 0;
        msg.sender.call.value(redeemableEther[msg.sender])(" ");
    }
}
