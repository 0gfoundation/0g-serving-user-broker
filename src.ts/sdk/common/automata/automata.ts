import { ethers } from 'ethers'
import {
    AUTOMATA_ABI,
    AUTOMATA_CONTRACT_ADDRESS,
    AUTOMATA_RPC,
} from '../../fine-tuning/const'

export class Automata {
    protected provider: any
    protected contract: ethers.Contract

    constructor() {
        this.provider = new ethers.JsonRpcProvider(AUTOMATA_RPC)
        this.contract = new ethers.Contract(
            AUTOMATA_CONTRACT_ADDRESS,
            AUTOMATA_ABI,
            this.provider
        )
    }

    async verifyQuote(rawQuote: string): Promise<boolean | undefined> {
        try {
            const [success] = await this.contract.verifyAndAttestOnChain(
                rawQuote
            )

            return success
        } catch (error) {
            throw error
        }
    }
}
