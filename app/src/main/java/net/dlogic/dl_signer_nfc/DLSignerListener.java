package net.dlogic.dl_signer_nfc;

public interface DLSignerListener {
    void finished(Boolean success, byte[] result, String... messages);
}
