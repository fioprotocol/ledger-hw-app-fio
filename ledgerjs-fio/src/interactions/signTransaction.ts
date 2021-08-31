import type { HexString, ParsedTransaction, ValidBIP32Path } from "types/internal"

import type {SignedTransactionData, Version } from "../types/public"
import { HARDENED, Transaction } from "../types/public"
import { chunkBy } from "../utils/ioHelpers"
import { INS } from "./common/ins"
import type { Interaction, SendParams } from "./common/types"
import { ensureLedgerAppVersionCompatible } from "./getVersion"
import { date_to_buf, uint16_to_buf, uint32_to_buf, buf_to_hex, hex_to_buf, path_to_buf } from "../utils/serialize"

const enum P1 {
  STAGE_INIT = 0x01,
  STAGE_FEE = 0x02,
  STAGE_WITNESSES = 0x03,
}

const send = (params: {
  p1: number,
  p2: number,
  data: Buffer,
  expectedResponseLength?: number
}): SendParams => ({ ins: INS.SIGN_TX, ...params })



export function* signTransaction(version: Version, parsedPath: ValidBIP32Path, chainId: HexString, tx: ParsedTransaction): Interaction<SignedTransactionData> {
    ensureLedgerAppVersionCompatible(version)
     
    //Initialize
    {
        const P2_UNUSED = 0x00
        const response = yield send({
            p1: P1.STAGE_INIT,
            p2: P2_UNUSED,
            data: Buffer.from(chainId, "hex"),
            expectedResponseLength: 0,
        })
    }
    //Send chainId
    {
        const P2_UNUSED = 0x00
        const response = yield send({
            p1: P1.STAGE_FEE,
            p2: P2_UNUSED,
            data: Buffer.concat([date_to_buf(tx.expiration), uint16_to_buf(tx.ref_block_num), uint32_to_buf(tx.ref_block_prefix)]),
            expectedResponseLength: 0,
        })
    }
    //Send witnesses
    const P2_UNUSED = 0x00
    const response = yield send({
        p1: P1.STAGE_WITNESSES,
        p2: P2_UNUSED,
        data: Buffer.concat([path_to_buf(parsedPath)]),
        expectedResponseLength: 65+32,
    })

    const [witnessSignature, hash] = chunkBy(response, [65, 32])
    return { txHashHex: buf_to_hex(hash), witness: {path: [44 + HARDENED, 235 + HARDENED, 0+ HARDENED, 0, 0], witnessSignatureHex: buf_to_hex(witnessSignature)}}
}
