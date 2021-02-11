package de.upb.crypto.craco.protocols;


public interface CommonInput {
    CommonInput EMPTY = new EmptyCommonInput();
    class EmptyCommonInput implements CommonInput {

    }
}
