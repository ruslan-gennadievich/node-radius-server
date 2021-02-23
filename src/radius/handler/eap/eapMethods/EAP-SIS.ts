// https://tools.ietf.org/html/rfc5281 TTLS v0
// https://tools.ietf.org/html/draft-funk-eap-ttls-v1-00 TTLS v1 (not implemented)
/* eslint-disable no-bitwise */
import * as fs from 'fs';
import * as tls from 'tls';
import * as crypto from 'crypto';
import * as NodeCache from 'node-cache';
import { RadiusPacket } from 'radius';
import debug from 'debug';
import { IPacketHandlerResult, PacketResponseCode } from '../../../../types/PacketHandler';
import { IEAPMethod } from '../../../../types/EAPMethod';
import { buildEAPResponse } from '../EAPHelper';


const log = debug('radius:eap:sis');
export class EAPSIS implements IEAPMethod {
	// constructor() {}
	private DataToSign_NodeCache = new NodeCache({ useClones: false, stdTTL: 40 });

	getEAPType(): number {
		return 4;
	}

	identify(identifier: number, _stateID: string): IPacketHandlerResult {
		const buff = Buffer.alloc(18);
		buff[0] = 16; // size head LE
		buff[1] = 0; // size head BE
		buff[2] = 3; // SignConf (0 - default in encryptor; 1 - only encryptor; 2 - encryptor+user)
		crypto.randomFillSync(buff, 3); // random data for sign
		const ServerRandom = buff.slice(2); // first two is size - slice it
		this.DataToSign_NodeCache.set(identifier, ServerRandom); // cache _stateID = buff
		return buildEAPResponse(identifier, 4, buff);
	}

	async handleMessage(
		_identifier: number,
		_stateID: string,
		_msg: Buffer,
		_orgRadiusPacket: RadiusPacket
	): Promise<IPacketHandlerResult> {
		if (_msg[0] === 1 && _msg.length === 3) {
			return {
				code: PacketResponseCode.AccessAccept,
			};
		}
		const DataToSign = this.DataToSign_NodeCache.get(_identifier) as Buffer;

		const beginOffset = 2; // EAP Header size (value_size)
		let [offset, len] = [beginOffset, 16];
		const server_challenge = _msg.slice(offset, offset + len);

		if (DataToSign.equals(server_challenge) === false) {
			// Проверяем, что клиент прислал то что мы ему отправили на подпись
			return { code: PacketResponseCode.AccessReject };
		}

		[offset, len] = [offset + len, 16];
		const peer_challenge = _msg.slice(offset, offset + len);

		// Sign Encryptor
		[offset, len] = [offset + len, 2];
		const ecr_sign_offset = _msg.slice(offset, offset + len).readUInt16LE(0);

		[offset, len] = [offset + len, 2];
		const ecr_sign_size = _msg.slice(offset, offset + len).readUInt16LE(0);

		// Sign User
		[offset, len] = [offset + len, 2];
		const user_sign_offset = _msg.slice(offset, offset + len).readUInt16LE(0);

		[offset, len] = [offset + len, 2];
		const user_sign_size = _msg.slice(offset, offset + len).readUInt16LE(0);

		// Cert Encryptor
		[offset, len] = [offset + len, 2];
		const ecr_cert_offset = _msg.slice(offset, offset + len).readUInt16LE(0);

		[offset, len] = [offset + len, 2];
		const ecr_cert_size = _msg.slice(offset, offset + len).readUInt16LE(0);

		// Cert User
		[offset, len] = [offset + len, 2];
		const user_cert_offset = _msg.slice(offset, offset + len).readUInt16LE(0);

		[offset, len] = [offset + len, 2];
		const user_cert_size = _msg.slice(offset, offset + len).readUInt16LE(0);

		// ======================
		const encryptorSign = _msg.slice(offset + len + ecr_sign_offset, offset + len + ecr_sign_size);
		const userSign = _msg.slice(offset + len + user_sign_offset, offset + len + user_sign_offset + user_sign_size);

		const encryptorCert = _msg.slice(offset + len + ecr_cert_offset, offset + len + ecr_cert_offset + ecr_cert_size);
		const userCert = _msg.slice(offset + len + user_cert_offset, offset + len + user_cert_offset + user_cert_size);
		
		let userCertBase64 = '';
		let encryptorCertBase64 = '';

		// ====== Parse encryptor cert =============
		if (encryptorCert[0] === 48) {
			// if cert in DER
			const base64 = Buffer.from(encryptorCert).toString('base64');
			encryptorCertBase64 = `-----BEGIN CERTIFICATE-----\n${base64}\n-----END CERTIFICATE-----`;
		}
		let secureContext = tls.createSecureContext({ cert: encryptorCertBase64 });
		// @ts-ignore
		let secureSocket = new tls.TLSSocket(null, { secureContext }); // socket null - its ok!
		const encrCertParsed = secureSocket.getCertificate();

		// ====== Parse user cert =============
		if (userCert[0] === 48) {
			// if cert in DER
			const base64 = Buffer.from(userCert).toString('base64');
			userCertBase64 = `-----BEGIN CERTIFICATE-----\n${base64}\n-----END CERTIFICATE-----`;
		}

		secureContext = tls.createSecureContext({ cert: userCertBase64 });
		// @ts-ignore
		secureSocket = new tls.TLSSocket(null, { secureContext }); // socket null - its ok!
		const userCertParsed = secureSocket.getCertificate();

		const encrCert_SN = encrCertParsed && encrCertParsed !== {} ? encrCertParsed['serialNumber'] : '';
		const userCert_SN = userCertParsed && encrCertParsed !== {} ? userCertParsed['serialNumber'] : '';

		// Check SN in DataBase

		// // Check Signarute
		if (encrCertParsed) {
			// @ts-ignore
			fs.writeFileSync('./tmp_data', Buffer.concat([server_challenge, Buffer.alloc(16)]));
			fs.writeFileSync('./tmp_encryptor.cer', encryptorCert);
			fs.writeFileSync('./tmp_sign.der', encryptorSign);
		}

		const buffer = Buffer.alloc(32 + 1 + 2);
		console.log('_stateID', _stateID);
		buffer.fill(_stateID, 2); // token
		buffer[0] = 32; //size LE
		//buffer[1] = 32; //size BE
		return buildEAPResponse(_identifier, 4, buffer);
	}
}