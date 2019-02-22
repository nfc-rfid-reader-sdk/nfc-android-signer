package net.dlogic.dl_signer_nfc;

public interface DLSignerListener {

    void signatureFinished(Boolean success, byte[] result, String... messages);
    void certReadFinished(Boolean success, byte[] result, String... messages);
}
