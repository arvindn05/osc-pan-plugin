/* Copyright 2016 Palo Alto Networks Inc.
 * All Rights Reserved.
 *    Licensed under the Apache License, Version 2.0 (the "License"); you may
 *    not use this file except in compliance with the License. You may obtain
 *    a copy of the License at
 *
 *         http://www.apache.org/licenses/LICENSE-2.0
 *
 *    Unless required by applicable law or agreed to in writing, software
 *    distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
 *    WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
 *    License for the specific language governing permissions and limitations
 *    under the License.
 */
package com.paloaltonetworks.osc.api;

import static com.paloaltonetworks.panorama.api.methods.PanoramaApiClient.*;
import static java.util.Collections.emptyList;
import static java.util.stream.Collectors.toList;

import java.io.IOException;
import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.Collections;
import java.util.List;
import java.util.Map;

import org.apache.commons.codec.binary.Base64;
import org.osc.sdk.manager.api.ManagerDeviceApi;
import org.osc.sdk.manager.element.ApplianceBootstrapInformationElement;
import org.osc.sdk.manager.element.ApplianceManagerConnectorElement;
import org.osc.sdk.manager.element.BootStrapInfoProviderElement;
import org.osc.sdk.manager.element.DistributedApplianceInstanceElement;
import org.osc.sdk.manager.element.ManagerDeviceElement;
import org.osc.sdk.manager.element.ManagerDeviceMemberElement;
import org.osc.sdk.manager.element.VirtualSystemElement;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.paloaltonetworks.osc.model.PANDeviceElement;
import com.paloaltonetworks.panorama.api.mapping.DeviceGroupResponse;
import com.paloaltonetworks.panorama.api.mapping.DeviceGroupsEntry;
import com.paloaltonetworks.panorama.api.mapping.SetConfigResponse;
import com.paloaltonetworks.panorama.api.methods.PanoramaApiClient;
import com.paloaltonetworks.utils.Messages;

/**
 * This documents "Device Management Apis"
 */
public class PANDeviceApi implements ManagerDeviceApi {

    // "I4745132";"I2306077";
    private static final Logger LOG = LoggerFactory.getLogger(PANDeviceApi.class);
    private static final String LICENSE_AUTH_CODE = "I7517916";
    private static final String SHOW_DEVICEGROUPS_CMD = "<show><devicegroups></devicegroups></show>";
    private static final String DAYS_FOR_VMAUTH_KEY = "8760";

    // TODO: use properties to configure!
    private static final long DEVGPS_SLEEP_MS = 1000L;
    private static final int DEVGPS_TIMEOUT_TRIES = 900;
    private static final int DEVGPS_TIMEOUT_TRIES_SHORT = 30;

    private String vmAuthKey = null;
    private VirtualSystemElement vs;
    private ApplianceManagerConnectorElement mc;
    private PanoramaApiClient panClient;

    public PANDeviceApi(ApplianceManagerConnectorElement mc, VirtualSystemElement vs, PanoramaApiClient panClient)
            throws Exception {
        this.vs = vs;
        this.mc = mc;
        this.panClient = panClient;
        this.vmAuthKey = this.panClient.getVMAuthKey(DAYS_FOR_VMAUTH_KEY);
    }

    @Override
    public boolean isDeviceGroupSupported() {
        return true;
    }

    @Override
    public ManagerDeviceElement getDeviceById(String id) throws Exception {

        if (id == null) {
            throw new IllegalArgumentException("Null device id is not allowed!");
        }

        return listDevices().stream().filter(de -> id.equals(de.getName())).findAny().orElse(null);
    }

    @Override
    public String findDeviceByName(String name) throws Exception {
        return getDeviceById(name) == null ? null : name;
    }

    @Override
    public List<? extends ManagerDeviceElement> listDevices() throws Exception {
        Map<String, String> queryStrings = this.panClient.makeOpCmdRequestParams(SHOW_DEVICEGROUPS_CMD);

        DeviceGroupResponse deviceGroupResponse = this.panClient.getRequest(queryStrings, DeviceGroupResponse.class);

        if (deviceGroupResponse.getDeviceGroups() != null
                && deviceGroupResponse.getDeviceGroups().getEntries() != null) {
            List<DeviceGroupsEntry> deviceGroups = deviceGroupResponse.getDeviceGroups().getEntries();
            return deviceGroups.stream().filter(dg -> dg != null)
                    .map(dg -> new PANDeviceElement(dg.getName(), dg.getName())).collect(toList());
        }

        return emptyList();
    }

    @SuppressWarnings("boxing")
    @Override
    public String createVSSDevice() throws Exception {
        // Create a device group in panorama
        // Information passed in by VSS to create device group
        // VSS is the device group
        LOG.info("Adding device group " + this.vs.getName());
        String devGroup = this.vs.getName();

        if (getDeviceById(devGroup) != null) {
            LOG.error("Device group {} already exists!", devGroup);
            return devGroup;
        }

        String element = PanoramaApiClient.makeEntryElement(devGroup, null, "OSC Device group - do not remove", null);
        element = element.replace("</entry>", "<devices/></entry>");
        Map<String, String> queryStrings = this.panClient.makeSetConfigRequestParams(XPATH_DEVGROUP_PREFIX, element,
                null);
        this.panClient.getRequest(queryStrings, SetConfigResponse.class).getStatus();
        String errorMessage = String.format("Commit failed when adding Device Group Name: %s", this.vs.getName());
        this.panClient.configCommitOrThrow(errorMessage);

        ManagerDeviceElement mde;
        for (int i = 0; (mde = getDeviceById(devGroup)) == null && i < DEVGPS_TIMEOUT_TRIES; i++) {
            Thread.sleep(DEVGPS_SLEEP_MS);
            if (i > DEVGPS_TIMEOUT_TRIES_SHORT) {
                LOG.warn("Device group {} still not added after {} seconds. Will keep trying for {} seconds", devGroup,
                        i + 1, DEVGPS_TIMEOUT_TRIES - i - 1);
            }
        }

        if (mde == null) {
            throw new IllegalStateException("Failed to add the device group after multiple tries: " + devGroup);
        }

        LOG.info("Device group {} added successfully.", devGroup);

        return devGroup; // TODO : one per vs?
    }

    @Override
    public void updateVSSDevice(ManagerDeviceElement device) throws Exception {
        createVSSDevice();
    }

    @Override
    public void deleteVSSDevice() throws Exception {
        LOG.info("Deleting device group " + this.vs.getName());

        String devGroup = this.vs.getName();

        if (getDeviceById(devGroup) == null) {
            LOG.error("Device group {} does not exist!", devGroup);
            return;
        }

        String xpath = XPATH_DEVGROUP_PREFIX + "/entry[ @name=\"" + devGroup + "\" ]";
        String element = PanoramaApiClient.makeEntryElement(devGroup);
        Map<String, String> queryStrings = this.panClient.makeRequestParams(DELETE_ACTION, CONFIG_TYPE, xpath, element,
                null);
        this.panClient.getRequest(queryStrings, SetConfigResponse.class);
        String errorMessage = String.format(
                "Commit failed when deleting Device Group Name: %s. Does it contain objects?", this.vs.getName());
        this.panClient.configCommitOrThrow(errorMessage);

        ManagerDeviceElement mde;
        for (int i = 0; (mde = getDeviceById(devGroup)) != null && i < DEVGPS_TIMEOUT_TRIES_SHORT; i++) {
            Thread.sleep(DEVGPS_SLEEP_MS);
        }

        if (mde != null) {
            LOG.error("Failed to delete {}. Delete manually from the appliance!", devGroup);
        }
    }

    @Override
    public String createDeviceMember(String name, String vserverIpAddress, String contactIpAddress, String ipAddress,
            String gateway, String prefixLength) throws Exception {

        // OSC calls this method to create a NGFW - pass this to panorama
        // Return panorqma device id
        return name;
    }

    @Override
    public String updateDeviceMember(ManagerDeviceMemberElement deviceElement, String name, String deviceHostName,
            String ipAddress, String mgmtIPAddress, String gateway, String prefixLength) throws Exception {

        // Redeploy need to thing through
        return null;
    }

    @Override
    public void deleteDeviceMember(String id) throws Exception {

        // Delete a firewall
    }

    @Override
    public ManagerDeviceMemberElement getDeviceMemberById(String id) throws Exception {

        // return device from panorma
        return null;
    }

    @Override
    public ManagerDeviceMemberElement findDeviceMemberByName(String name) throws Exception {

        return null;
    }

    @Override
    public List<? extends ManagerDeviceMemberElement> listDeviceMembers() throws Exception {

        return Collections.emptyList();
    }

    @Override
    public boolean isUpgradeSupported(String modelType, String prevSwVersion, String newSwVersion) throws Exception {

        return false;
    }

    @Override
    public byte[] getDeviceMemberConfigById(String mgrDeviceId) throws Exception {

        return null;
    }

    @Override
    public byte[] getDeviceMemberConfiguration(DistributedApplianceInstanceElement dai) {

        return null;
    }

    @Override
    public byte[] getDeviceMemberAdditionalConfiguration(DistributedApplianceInstanceElement dai) {

        return null;
    }

    protected byte[] readFile(String path, Charset encoding) throws IOException {
        byte[] encoded = Files.readAllBytes(Paths.get(path));
        return Base64.encodeBase64(new String(encoded, encoding).getBytes());
    }

    @Override
    public ApplianceBootstrapInformationElement getBootstrapinfo(BootStrapInfoProviderElement bootStrapInfo) {

        PANApplianceBootstrapInformationElement bootstrapElement = new PANApplianceBootstrapInformationElement();
        byte[] nullEntry = Base64.encodeBase64(("").getBytes());
        try {
            bootstrapElement.addBootstrapFile("/config/init-cfg.txt", getInitCfg(bootStrapInfo));
            bootstrapElement.addBootstrapFile("/config/bootstrap.xml", getBootstrapXML(bootStrapInfo));
            bootstrapElement.addBootstrapFile("/license/authcodes", getLicense());
            bootstrapElement.addBootstrapFile("/content", nullEntry);
            bootstrapElement.addBootstrapFile("/software", nullEntry);
        } catch (Exception e) {
            e.printStackTrace();
        }
        return bootstrapElement;
    }

    protected byte[] getInitCfg(BootStrapInfoProviderElement bootStrapInfo) {

        // Pass in bootstrap info for device
        // Same info for all devices
        // use vss element to determine device group
        // give me config drive info for device group
        byte[] encoded;
        String configString = Messages.getString("PANDeviceApi.init", bootStrapInfo.getName(), this.mc.getIpAddress(),
                this.vs.getName(), this.vmAuthKey);
        encoded = (configString).getBytes(StandardCharsets.UTF_8);
        //return Base64.encode(encoded);
        return encoded;
    }

    protected byte[] getLicense() {
        byte[] encoded;
        encoded = (LICENSE_AUTH_CODE.getBytes(StandardCharsets.UTF_8));
        return encoded;
    }

    protected byte[] getBootstrapXML(BootStrapInfoProviderElement bootStrapInfo) {
        byte[] encoded;
        String configString;
        configString = Messages.getString("PANDeviceApi.bootstrap", bootStrapInfo.getName(),
                this.mc.getIpAddress());

        encoded = (configString.getBytes(StandardCharsets.UTF_8));
        return encoded;
    }

    @Override
    public void close() {

    }

}
