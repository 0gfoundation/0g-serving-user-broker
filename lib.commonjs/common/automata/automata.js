"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.Automata = void 0;
const ethers_1 = require("ethers");
const const_1 = require("../../fine-tuning/const");
class Automata {
    provider;
    contract;
    constructor() {
        this.provider = new ethers_1.ethers.JsonRpcProvider(const_1.AUTOMATA_RPC);
        this.contract = new ethers_1.ethers.Contract(const_1.AUTOMATA_CONTRACT_ADDRESS, const_1.AUTOMATA_ABI, this.provider);
    }
    async verifyQuote(rawQuote) {
        try {
            const [success] = await this.contract.verifyAndAttestOnChain(rawQuote);
            return success;
        }
        catch (error) {
            throw error;
        }
    }
}
exports.Automata = Automata;
//# sourceMappingURL=automata.js.map