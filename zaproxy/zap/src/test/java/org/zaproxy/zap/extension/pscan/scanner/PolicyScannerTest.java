package org.zaproxy.zap.extension.pscan.scanner;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.zaproxy.zap.extension.policyloader.Rule;
import org.zaproxy.zap.extension.policyloader.exceptions.DuplicatePolicyException;

import java.lang.reflect.Array;
import java.util.ArrayList;
import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

class PolicyScannerTest {
    PolicyScanner policyScanner;

    @BeforeEach
    void setup() {
        policyScanner = new PolicyScanner();
    }

    @Test
    void getPluginId() {
        assertEquals( 500001,    policyScanner.getPluginId());
    }

    @Test
    void getName() {
        assertEquals("Policy scanner", policyScanner.getName());
    }

    @Test
    void addPolicy() {
        String policyName= "testPolicy";
        List<Rule> rules = new ArrayList<>();

        try {
            policyScanner.addPolicy("testPolicy", rules);
        } catch (DuplicatePolicyException e) {
            fail("Should not have thrown exception");
        }
        assertThrows(DuplicatePolicyException.class, () -> {
            policyScanner.addPolicy("testPolicy", rules);
        });
    }

    @Test
    void scanHttpRequestSend() {
        // not active for now
    }

    @Test
    void scanHttpResponseReceive() {
        // todo test
    }

    // todo test remove policy
}