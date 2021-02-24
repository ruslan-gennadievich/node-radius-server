// https://tools.ietf.org/html/rfc5281 TTLS v0
// https://tools.ietf.org/html/draft-funk-eap-ttls-v1-00 TTLS v1 (not implemented)
/* eslint-disable no-bitwise */
import * as tls from 'tls';
import * as crypto from 'crypto';
import { execSync } from 'child_process';
import * as NodeCache from 'node-cache';
import { RadiusPacket } from 'radius';
import debug from 'debug';
import { IPacketHandlerResult, PacketResponseCode } from '../../../../types/PacketHandler';
import { IEAPMethod } from '../../../../types/EAPMethod';
import { buildEAPResponse } from '../EAPHelper';

const log = debug('radius:eap:sis');

enum IModeCheckSign {
	DEFAULT_IN_ENCRYPTOR = 1,
	ONLY_ENCRYPTOR = 2,
	ENCRYPTOR_AND_USER = 3,
}

interface ICheckSign {
	valid: boolean;
	stdout: string;
	error: string;
}

export class EAPSIS implements IEAPMethod {
	// constructor() {}
	private DataToSign_NodeCache = new NodeCache({ useClones: false, stdTTL: 40 });

	private ModeCheckSign: IModeCheckSign = IModeCheckSign.ENCRYPTOR_AND_USER; // (1 - default in encryptor; 2 - only encryptor; 3 - encryptor+user)

	private checkSign(dataRaw: Buffer, signDer: Buffer, certBase64: string): ICheckSign {
		try {
			const dataRawBase64 = dataRaw.toString('base64');
			const signDerBase64 = signDer.toString('base64');
			const stdout = execSync(`./tool-verify-data ${dataRawBase64} ${signDerBase64} ${certBase64}`).toString();
			const valid = stdout.includes('Verified OK');
			return { stdout, valid, error: '' };
		} catch (err) {
			return { stdout: '', valid: false, error: err.message };
		}
	}

	private SendToken(_identifier, _stateID) {
		const buffer = Buffer.alloc(32 + 1 + 2);
		console.log('_stateID', _stateID);
		buffer.fill(_stateID, 2); // _stateID as token
		buffer[0] = 32; // size LE
		// buffer[1] = 32; // size BE
		return buildEAPResponse(_identifier, 4, buffer);
	}

	getEAPType(): number {
		// EAPType in strongswan (src/libstrongswan/eap/eap.h)
		return 4; // NEED 253    СНАЧАЛА ИСПРАВИТЬ ЧТО СЕРВЕР ПРИСЫЛАЕТ NAK !!!
	}

	identify(identifier: number, _stateID: string): IPacketHandlerResult {
		const buff = Buffer.alloc(18);
		buff[0] = 16; // size head LE
		buff[1] = 0; // size head BE
		buff[2] = this.ModeCheckSign;
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
		encryptorCertBase64 =
			encryptorCert[0] === 48
				? Buffer.from(encryptorCert).toString('base64')
				: encryptorCert.toString();
		if (!encryptorCertBase64.startsWith('-----BEGIN CERTIFICATE-----'))
			encryptorCertBase64 = `-----BEGIN CERTIFICATE-----\n${encryptorCertBase64}\n-----END CERTIFICATE-----`;

		let secureContext = tls.createSecureContext({ cert: encryptorCertBase64 });
		// @ts-ignore
		let secureSocket = new tls.TLSSocket(null, { secureContext }); // socket null - its ok!
		const encrCertParsed = secureSocket.getCertificate();

		// ====== Parse user cert =============
		userCertBase64 =
			userCert[0] === 48 ? Buffer.from(userCert).toString('base64') : userCert.toString();
		if (!userCertBase64.startsWith('-----BEGIN CERTIFICATE-----'))
			userCertBase64 = `-----BEGIN CERTIFICATE-----\n${userCertBase64}\n-----END CERTIFICATE-----`;

		secureContext = tls.createSecureContext({ cert: userCertBase64 });
		// @ts-ignore
		secureSocket = new tls.TLSSocket(null, { secureContext }); // socket null - its ok!
		const userCertParsed = secureSocket.getCertificate();

		const encrCert_SN = encrCertParsed && encrCertParsed !== {} ? encrCertParsed['serialNumber'] : '';
		const userCert_SN = userCertParsed && encrCertParsed !== {} ? userCertParsed['serialNumber'] : '';

		// Check SN in DataBase

		// Verify Signatures
		const DataToHash = Buffer.concat([server_challenge, peer_challenge]);

		if (this.ModeCheckSign === IModeCheckSign.DEFAULT_IN_ENCRYPTOR) {
			console.log(`check method ${this.ModeCheckSign} not implemented`);
			if (encryptorCert.length > 0 && encryptorSign.length > 0) {
				//
			}
			if (userCert.length > 0 && userSign.length > 0) {
				//
			}
		} else if (this.ModeCheckSign === IModeCheckSign.ONLY_ENCRYPTOR) {
			console.log(`check method ${this.ModeCheckSign} not implemented`);
		} else if (this.ModeCheckSign === IModeCheckSign.ENCRYPTOR_AND_USER) {
			const checkEncryptorResult = this.checkSign(
				DataToHash,
				encryptorSign,
				encryptorCert.toString('base64')
			);

			if (checkEncryptorResult.valid === false) {
				if (checkEncryptorResult.error.length > 0)
					console.log('Error check encryptor sign: ', checkEncryptorResult.error);

				return { code: PacketResponseCode.AccessReject };
			}

			const checkUserResult = this.checkSign(DataToHash, userSign, userCert.toString('base64'));
			if (checkUserResult.valid === false) {
				if (checkEncryptorResult.error.length > 0)
					console.log('Error check user sign: ', checkUserResult.error);

				return { code: PacketResponseCode.AccessReject };
			}
			return this.SendToken(_identifier, _stateID);
		} else {
			console.log(`unknow check method ${this.ModeCheckSign}`);
			return { code: PacketResponseCode.AccessReject };
		}
		return { code: PacketResponseCode.AccessReject };
	}
}
