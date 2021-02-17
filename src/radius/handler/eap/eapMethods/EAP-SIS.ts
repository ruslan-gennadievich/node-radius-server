// https://tools.ietf.org/html/rfc5281 TTLS v0
// https://tools.ietf.org/html/draft-funk-eap-ttls-v1-00 TTLS v1 (not implemented)
/* eslint-disable no-bitwise */
import * as fs from 'fs';
import * as tls from 'tls';
import { RadiusPacket } from 'radius';
import debug from 'debug';
import { IPacketHandlerResult, PacketResponseCode } from '../../../../types/PacketHandler';
import { IEAPMethod } from '../../../../types/EAPMethod';
import { buildEAPResponse } from '../EAPHelper';

const log = debug('radius:eap:sis');
export class EAPSIS implements IEAPMethod {
	// constructor() {}

	getEAPType(): number {
		return 4;
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
		fs.writeFileSync('recived_buffer.bin', _msg);

		if (_msg[0] === 1 && _msg.length === 3) {
			return {
				code: PacketResponseCode.AccessAccept,
			};
		}

		const server_challenge = _msg.slice(1, 17);
		const peer_challenge = _msg.slice(17, 33);

		// Encryptor Sign
		const ecr_sign_offset = _msg.slice(33, 35).readUInt16BE(0);
		const ecr_sign_size = _msg.slice(35, 37).readUInt16BE(0);
		// User Sign
		const user_sign_offset = _msg.slice(37, 39).readUInt16BE(0);
		const user_sign_size = _msg.slice(39, 41).readUInt16BE(0);

		// Encryptor Cert
		const ecr_cert_offset = _msg.slice(41, 43).readUInt16BE(0);
		const ecr_cert_size = _msg.slice(43, 45).readUInt16BE(0);
		// User Cert
		const user_cert_offset = _msg.slice(45, 47).readUInt16BE(0);
		const user_cert_size = _msg.slice(47, 49).readUInt16BE(0);
		// ======================
		const encryptorSign = _msg.slice(50 + ecr_sign_offset, 49 + ecr_sign_size);
		const userSign = _msg.slice(50 + user_sign_offset, 49 + user_sign_offset + user_sign_size);

		let encryptorCert = _msg.slice(50 + ecr_cert_offset, 49 + ecr_cert_offset + ecr_cert_size);
		let userCert = _msg.slice(50 + user_cert_offset, 49 + user_cert_offset + user_cert_size);

		// ====== Parse encryptor cert =============
		let certBase64 = '';

		if (true) { //TEST
			encryptorCert = fs.readFileSync('./4c0f5dddcdedfe88950dc36f697a50b11225c9e1.cer');
			userCert = fs.readFileSync('./4c0f5dddcdedfe88950dc36f697a50b11225c9e1.cer');
		}

		if (encryptorCert[0] === 48) {
			// if cert in DER
			const base64 = Buffer.from(encryptorCert).toString('base64');
			certBase64 = `-----BEGIN CERTIFICATE-----\n${base64}\n-----END CERTIFICATE-----`;
		}

		let secureContext = tls.createSecureContext({ cert: certBase64 });
		// @ts-ignore
		let secureSocket = new tls.TLSSocket(null, { secureContext }); // socket null - its ok!
		const encrCertParsed = secureSocket.getCertificate();

		// ====== Parse user cert =============

		if (userCert[0] === 48) {
			// if cert in DER
			const base64 = Buffer.from(userCert).toString('base64');
			certBase64 = `-----BEGIN CERTIFICATE-----\n${base64}\n-----END CERTIFICATE-----`;
		}

		secureContext = tls.createSecureContext({ cert: certBase64 });
		// @ts-ignore
		secureSocket = new tls.TLSSocket(null, { secureContext }); // socket null - its ok!

		const userCertParsed = secureSocket.getCertificate();

		const encrCert_SN = encrCertParsed && encrCertParsed !== {} ? encrCertParsed['serialNumber'] : '';
		const userCert_SN = userCertParsed && encrCertParsed !== {} ? userCertParsed['serialNumber'] : '';

		// Check SN in DataBase

		// ..

		// Check Signarute
		for (let i = 0; i < 16; i++) {
			if (encryptorSign[i] !== 0x11 || userSign[i] !== 0x22) {
				console.log('Check Sign ERROR!!!')
				return {
					code: PacketResponseCode.AccessReject,
				};
			}
		}

		let buffer = Buffer.alloc(32 + 1 + 2);
		buffer[0] = 32; //size BE
		//buffer[1] = 32; //size LE

		// token next
		buffer[2] = 1;
		buffer[3] = 2;
		buffer[4] = 3;
		buffer[5] = 4;
		return buildEAPResponse(_identifier, 4, buffer);
	}
}
