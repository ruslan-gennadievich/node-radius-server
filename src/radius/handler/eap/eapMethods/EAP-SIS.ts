// https://tools.ietf.org/html/rfc5281 TTLS v0
// https://tools.ietf.org/html/draft-funk-eap-ttls-v1-00 TTLS v1 (not implemented)
/* eslint-disable no-bitwise */
import { RadiusPacket } from 'radius';
import debug from 'debug';
import { IPacketHandlerResult, PacketResponseCode } from '../../../../types/PacketHandler';
import { IEAPMethod } from '../../../../types/EAPMethod';
import { IAuthentication } from '../../../../types/Authentication';
import { buildEAPResponse } from '../EAPHelper';

const log = debug('radius:eap:sis');
export class EAPSIS implements IEAPMethod {
	constructor(private authentication: IAuthentication) {}

	getEAPType(): number {
		return 253;
	}

	identify(identifier: number, _stateID: string): IPacketHandlerResult {
		const buff = Buffer.alloc(18);
		buff[0] = 16;
		return buildEAPResponse(identifier, 4, buff);
	}

	async handleMessage(
		_identifier: number,
		_stateID: string,
		_msg: Buffer,
		_orgRadiusPacket: RadiusPacket
	): Promise<IPacketHandlerResult> {
		// const identifier = _msg.slice(0, 1).readUInt8(0);
		// const code = _msg.slice(1, 2).readUInt8(0);
		// const length = _msg.slice(2, 4).readUInt16BE(0);
		// const type = _msg.slice(4, 6).readUInt8(0);

		log(_msg);

		if (_msg[0] === 1 && _msg.length === 3) {
			return {
				code: PacketResponseCode.AccessAccept,
			};
		}

		const value_size = _msg.slice(0, 2).readUInt16LE(0);
		const num_signatures = _msg[2];
		const value_arr = _msg.slice(3, value_size);
		const signature1 = value_arr.slice(0, 64);
		const signature2 = value_arr.slice(64, 128);

		const certificate1 = value_arr.slice(128, 1500);
		const certificate2 = value_arr.slice(1500, 3000);

		// do sql certificate1, certificate1

		for (let i = 0; i < 16; i++) {
			if (signature1[i] !== 0x11 || signature2[i] !== 0x22) {
				return {
					code: PacketResponseCode.AccessReject,
				};
			}
		}

		let buffer = Buffer.alloc(200 + 1 + 2);
		buffer[0] = 201;
		//buffer[1] = (203 >> 8) & 255;

		return buildEAPResponse(_identifier, 4, buffer);
	}

	// buildEAPResponseBig(
	// 	identifier: number,
	// 	msgType: number,
	// 	data?: Buffer
	// ): IPacketHandlerResult {
	// 	return {
	// 		code: PacketResponseCode.AccessChallenge,
	// 		attributes: [['EAP-Message', buildEAP(identifier, msgType, data)]],
	// 	};
	// }
}
