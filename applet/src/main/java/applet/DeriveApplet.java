package applet;

import javacard.framework.APDU;
import javacard.framework.Applet;
import javacard.framework.ISO7816;
import javacard.framework.ISOException;

import javacard.framework.*;
import javacard.security.*;

public class DeriveApplet extends Applet  {

    protected static final byte CLA_DERIVEAPPLET = (byte)0xB0;
    protected static final byte INS_TEST = (byte)0x00;
    protected static final byte INS_DERIVE = (byte)0x01;

    protected static final short RES_ERR_GENERAL = (short)0x6B00;

    static final short PRIVATE_KEY_SIZE = 32;
    static final short PUBLIC_KEY_SIZE = 65;
    static final short CHAIN_CODE_SIZE = 32;
    static final byte UID_LENGTH = 16;
    static final byte KEY_PATH_MAX_DEPTH = 10;

    private byte[] tmpPath;
    private short tmpPathLen;
    private byte[] keyPath;
    private short keyPathLen;
    private byte[] derivationOutput;
    private byte[] masterChainCode;
    private byte[] altChainCode;
    private byte[] chainCode;
    private ECPublicKey masterPublic;
    private ECPrivateKey masterPrivate;
    private Crypto crypto;
    private SECP256k1 secp256k1;
    private byte[] uid;
    private byte[] pubkeyBuffer;

    public DeriveApplet(byte[] bArray, short bOffset, byte bLength) {
        crypto = new Crypto();
        secp256k1 = new SECP256k1();

        uid = new byte[UID_LENGTH];
        crypto.random.generateData(uid, (short) 0, UID_LENGTH);

        masterPublic = (ECPublicKey) KeyBuilder.buildKey(KeyBuilder.TYPE_EC_FP_PUBLIC, SECP256k1.SECP256K1_KEY_SIZE, false);
        masterPrivate = (ECPrivateKey) KeyBuilder.buildKey(KeyBuilder.TYPE_EC_FP_PRIVATE, SECP256k1.SECP256K1_KEY_SIZE, false);
        masterChainCode = new byte[CHAIN_CODE_SIZE];
        altChainCode = new byte[CHAIN_CODE_SIZE];
        chainCode = masterChainCode;

        tmpPath = JCSystem.makeTransientByteArray((short)(KEY_PATH_MAX_DEPTH * 4), JCSystem.CLEAR_ON_RESET);
        keyPath = new byte[KEY_PATH_MAX_DEPTH * 4];
        derivationOutput = JCSystem.makeTransientByteArray((short) (Crypto.KEY_SECRET_SIZE + CHAIN_CODE_SIZE), JCSystem.CLEAR_ON_RESET);
        pubkeyBuffer = JCSystem.makeTransientByteArray(PUBLIC_KEY_SIZE, JCSystem.CLEAR_ON_RESET);

        register();
    }

    public static void install(byte[] bArray, short bOffset, byte bLength)
    {
        new DeriveApplet(bArray, bOffset, bLength);
    }

    @Override
    public boolean select() {
        return true;
    }

    @Override
    public void process(APDU apdu) throws ISOException {
        // get the buffer with incoming APDU
        byte[] apduBuffer = apdu.getBuffer();

        // ignore the applet select command dispatched to the process
        if (selectingApplet()) {
            return;
        }

        try {
            // APDU instruction parser
            if (apduBuffer[ISO7816.OFFSET_CLA] == CLA_DERIVEAPPLET) {
                switch (apduBuffer[ISO7816.OFFSET_INS]) {
                    case INS_TEST:
                        break;
                    case INS_DERIVE:
                        this.testDoDerive(apdu);
                        break;
                    default:
                        // The INS code is not supported by the dispatcher
                        ISOException.throwIt(RES_ERR_GENERAL);
                        break;
                }
            } else {
                ISOException.throwIt(RES_ERR_GENERAL);
            }
        } catch (ISOException e) {
            throw e; // Our exception from code, just re-emit
        } catch (Exception e) {
            ISOException.throwIt(RES_ERR_GENERAL);
        }
    }

    // PRIVATE KEY [32B] | PUBLIC KEY [65B] | CHAIN CODE [32B] | PATH
    private void testDoDerive(APDU apdu) {
        byte[] apduBuffer = apdu.getBuffer();
        short dataLength = (short) (apduBuffer[ISO7816.OFFSET_LC] & 0xFF);

        // 1. extended - set private key and chaincode, derive public key
        saveKeys(apduBuffer, ISO7816.OFFSET_CDATA);

        // 2. prepare for derivation
        short pathLen = (short) (dataLength - (PRIVATE_KEY_SIZE + PUBLIC_KEY_SIZE + CHAIN_CODE_SIZE));
        preparePath(apduBuffer,
                (short) (ISO7816.OFFSET_CDATA + PRIVATE_KEY_SIZE + PUBLIC_KEY_SIZE + CHAIN_CODE_SIZE),
                pathLen);

        doDerive(apduBuffer, ISO7816.OFFSET_CDATA);
    }

    private void saveKeys(byte[] apduBuffer, short offset) {
        short privOffset = (short) (offset + 0);
        masterPrivate.setS(apduBuffer, privOffset, PRIVATE_KEY_SIZE);

        short pubOffset = (short) (offset + 32);
        masterPublic.setW(apduBuffer, pubOffset, PUBLIC_KEY_SIZE);

        short chainOffset = (short) (offset + PRIVATE_KEY_SIZE + PUBLIC_KEY_SIZE);
        Util.arrayCopy(apduBuffer, chainOffset, masterChainCode, (short) 0, CHAIN_CODE_SIZE);
    }

    private void preparePath(byte[] apduBuffer, short pathOff, short pathLen) {
        short newPathLen = pathLen;
        short pathLenOff = 0;

        if (((short) (pathLen % 4) != 0) || (newPathLen > keyPath.length)) {
            ISOException.throwIt(ISO7816.SW_WRONG_DATA);
        }

        Util.arrayCopyNonAtomic(keyPath, (short) 0, tmpPath, (short) 0, pathLenOff);
        Util.arrayCopyNonAtomic(apduBuffer, pathOff, tmpPath, pathLenOff, pathLen);
        tmpPathLen = newPathLen;
    }

   /* Internal derivation function, called by DERIVE KEY and EXPORT KEY
    * @param apduBuffer the APDU buffer
    * @param off the offset in the APDU buffer relative to the data field
    */
    private void doDerive(byte[] apduBuffer, short off) {

        if (tmpPathLen == 0) {
            masterPrivate.getS(derivationOutput, (short) 0);
            return;
        }

        short scratchOff = (short) (ISO7816.OFFSET_CDATA + off);
        short dataOff = (short) (scratchOff + Crypto.KEY_DERIVATION_SCRATCH_SIZE);

        short pubKeyOff = (short) (dataOff + masterPrivate.getS(apduBuffer, dataOff));
        pubKeyOff = Util.arrayCopyNonAtomic(chainCode, (short) 0, apduBuffer, pubKeyOff, CHAIN_CODE_SIZE);

        if (!crypto.bip32IsHardened(tmpPath, (short) 0)) {
            masterPublic.getW(apduBuffer, pubKeyOff);
        } else {
            apduBuffer[pubKeyOff] = 0;
        }

        for (short i = 0; i < tmpPathLen; i += 4) {
            if (i > 0) {
                Util.arrayCopyNonAtomic(derivationOutput, (short) 0, apduBuffer, dataOff, (short) (Crypto.KEY_SECRET_SIZE + CHAIN_CODE_SIZE));

                if (!crypto.bip32IsHardened(tmpPath, i)) {
                    secp256k1.derivePublicKey(apduBuffer, dataOff, apduBuffer, pubKeyOff);
                } else {
                    apduBuffer[pubKeyOff] = 0;
                }
            }

            if (!crypto.bip32CKDPriv(tmpPath, i, apduBuffer, scratchOff, apduBuffer, dataOff, derivationOutput, (short) 0)) {
                ISOException.throwIt(ISO7816.SW_DATA_INVALID);
            }
        }
    }
}
