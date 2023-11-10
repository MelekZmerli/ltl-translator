pragma solidity 0.4.25;

contract EtherLotto {
    address public bank;
    struct GameRecord {
        address winner;
        uint amount;
    }
    uint8 gameNum;
    GameRecord[] LottoLog;
    bool won;
    uint constant TICKET_AMOUNT = 10;
    uint constant FEE_AMOUNT = 1;
    uint public pot;

    function EtherLotto() {
        bank = msg.sender;
        won = false;
        gameNum = 0;
    }

    function RestartLotto() {
        require(msg.sender == bank);
        require(won == true);
        require(pot == 0);
        won = false;
        gameNum += 1;
    }

    function playTicket() payable {
        require(msg.value == TICKET_AMOUNT);
        require(won == false);
        pot += msg.value;
        uint random = uint(sha3(block.timestamp)) % 2;
        if (random == 0) {
            bank.call.value(FEE_AMOUNT)(" ");
            won = true;
            GameRecord gr;
            gr.winner = msg.sender;
            gr.amount = pot - FEE_AMOUNT;
            LottoLog[gameNum] = gr;
        }
    }

    function getPot() {
        require(won == true);
        if (msg.sender == LottoLog[gameNum].winner) {
            msg.sender.call.value(LottoLog[gameNum].amount)(" ");
            pot = 0;
        }
    }
}
