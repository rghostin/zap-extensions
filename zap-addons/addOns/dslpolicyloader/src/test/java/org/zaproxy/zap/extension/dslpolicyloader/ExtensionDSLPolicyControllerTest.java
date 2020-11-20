package org.zaproxy.zap.extension.dslpolicyloader;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertTrue;

class ExtensionDSLPolicyControllerTest {

    ExtensionDSLPolicyController controller;

    @BeforeEach
    void setup() {
        controller = new ExtensionDSLPolicyController();
    }

    @Test
    void hook() {
        // Test as Scenario test
    }

    @Test
    void canUnload() {
        assertTrue(controller.canUnload());
    }

    @Test
    void unload() {
        // Nothing to do
    }

    @Test
    void getSelectedTextFiles() {
        // Test as Scenario test
    }

    @Test
    void buildViolationsReport() {
        // Test as Scenario test
    }

    @Test
    void displayPolicies() {
        // Test as Scenario test
    }
}