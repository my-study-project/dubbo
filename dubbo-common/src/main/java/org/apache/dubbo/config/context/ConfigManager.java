/*
 * Licensed to the Apache Software Foundation (ASF) under one or more
 * contributor license agreements.  See the NOTICE file distributed with
 * this work for additional information regarding copyright ownership.
 * The ASF licenses this file to You under the Apache License, Version 2.0
 * (the "License"); you may not use this file except in compliance with
 * the License.  You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.apache.dubbo.config.context;

import org.apache.dubbo.common.context.ApplicationExt;
import org.apache.dubbo.common.extension.DisableInject;
import org.apache.dubbo.common.logger.Logger;
import org.apache.dubbo.common.logger.LoggerFactory;
import org.apache.dubbo.common.utils.CollectionUtils;
import org.apache.dubbo.common.utils.StringUtils;
import org.apache.dubbo.config.AbstractConfig;
import org.apache.dubbo.config.ApplicationConfig;
import org.apache.dubbo.config.ConfigCenterConfig;
import org.apache.dubbo.config.ConfigKeys;
import org.apache.dubbo.config.MetadataReportConfig;
import org.apache.dubbo.config.MetricsConfig;
import org.apache.dubbo.config.MonitorConfig;
import org.apache.dubbo.config.ProtocolConfig;
import org.apache.dubbo.config.RegistryConfig;
import org.apache.dubbo.config.SslConfig;
import org.apache.dubbo.rpc.model.ApplicationModel;

import java.util.Arrays;
import java.util.Collection;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;

import static java.util.Optional.ofNullable;
import static org.apache.dubbo.config.AbstractConfig.getTagName;

/**
 * A lock-free config manager (through ConcurrentHashMap), for fast read operation.
 * The Write operation lock with sub configs map of config type, for safely check and add new config.
 *
 * ConfigManager存储了所有dubbo的配置对象：RegistryConfig、ConsumerConfig、ModuleConfig、ProtocolConfig、ProviderConfig、ApplicationConfig、MonitorConfig。
 * 类似于一个本地的配置中心，如果要查询配置信息，访问ConfigManager获取对应的配置对象即可，任何配置对象修改了，都要刷新ConfigManager，比如ApplicationConfig修改了属性值，便会调用refreshAll方法修改ConfigManager。
 * 这些配置对象都存储在该对象的属性configsCache中，该属性是一个HashMap对象，因为HashMap不是线程安全的，所以提供了属性lock（ReadWriteLock对象）对访问属性configsCache的操作加锁。
 * ConfigManager提供了大量的setXXX和addXXX方法，这些方法最终都是调用addConfig方法，addConfig方法将配置对象添加到属性configsCache中。
 * 属性configsCache的类型是Map<String, Map<String, AbstractConfig>>，是一个两层Map结构，第一层的key是配置类名字的变体，比如调用addMetadataReports增加MetadataReportConfig对象，那么第一层的key是metadata-report，也就是将类名字的Config去掉，然后在类名字中大写字母前加“-”，最后将所有的大写字母变为小写字母。第二层的key是配置对象中的id属性的值，如果没有设置id值，默认使用类名字+“#default”作为key。
 * 在dubbo中，一般访问ConfigManager，是使用ApplicationModel.getConfigManager()通过SPI获取对象的。
 * 因为AbstractConfig的addIntoConfigManager方法有注解@PostConstruct，因此在AbstractConfig对象创建完毕后，spring会自动调用addIntoConfigManager方法，在该方法中将配置对象添加到ConfigManager中。通过addIntoConfigManager方法保证了所有的配置对象都会存储到ConfigManager中。
 * DubboBootstrap也提供了大量的方法用于向ConfigManager中添加配置对象以及从ConfigManager中获取配置对象。
 */
public class ConfigManager extends AbstractConfigManager implements ApplicationExt {

    private static final Logger logger = LoggerFactory.getLogger(ConfigManager.class);

    public static final String NAME = "config";
    public static final String BEAN_NAME = "dubboConfigManager";
    public static final String DUBBO_CONFIG_MODE = ConfigKeys.DUBBO_CONFIG_MODE;


    public ConfigManager(ApplicationModel applicationModel) {
        super(applicationModel, Arrays.asList(ApplicationConfig.class, MonitorConfig.class,
            MetricsConfig.class, SslConfig.class, ProtocolConfig.class, RegistryConfig.class, ConfigCenterConfig.class,
            MetadataReportConfig.class));
    }


// ApplicationConfig correlative methods

    /**
     * Set application config
     *
     * @param application
     * @return current application config instance
     */
    @DisableInject
    public void setApplication(ApplicationConfig application) {
        addConfig(application);
    }

    public Optional<ApplicationConfig> getApplication() {
        return ofNullable(getSingleConfig(getTagName(ApplicationConfig.class)));
    }

    public ApplicationConfig getApplicationOrElseThrow() {
        return getApplication().orElseThrow(() -> new IllegalStateException("There's no ApplicationConfig specified."));
    }

    // MonitorConfig correlative methods

    @DisableInject
    public void setMonitor(MonitorConfig monitor) {
        addConfig(monitor);
    }

    public Optional<MonitorConfig> getMonitor() {
        return ofNullable(getSingleConfig(getTagName(MonitorConfig.class)));
    }

    @DisableInject
    public void setMetrics(MetricsConfig metrics) {
        addConfig(metrics);
    }

    public Optional<MetricsConfig> getMetrics() {
        return ofNullable(getSingleConfig(getTagName(MetricsConfig.class)));
    }

    @DisableInject
    public void setSsl(SslConfig sslConfig) {
        addConfig(sslConfig);
    }

    public Optional<SslConfig> getSsl() {
        return ofNullable(getSingleConfig(getTagName(SslConfig.class)));
    }

    // ConfigCenterConfig correlative methods

    public void addConfigCenter(ConfigCenterConfig configCenter) {
        addConfig(configCenter);
    }

    public void addConfigCenters(Iterable<ConfigCenterConfig> configCenters) {
        configCenters.forEach(this::addConfigCenter);
    }

    public Optional<Collection<ConfigCenterConfig>> getDefaultConfigCenter() {
        Collection<ConfigCenterConfig> defaults = getDefaultConfigs(getConfigsMap(getTagName(ConfigCenterConfig.class)));
        if (CollectionUtils.isEmpty(defaults)) {
            defaults = getConfigCenters();
        }
        return Optional.ofNullable(defaults);
    }

    public Optional<ConfigCenterConfig> getConfigCenter(String id) {
        return getConfig(ConfigCenterConfig.class, id);
    }

    public Collection<ConfigCenterConfig> getConfigCenters() {
        return getConfigs(getTagName(ConfigCenterConfig.class));
    }

    // MetadataReportConfig correlative methods

    public void addMetadataReport(MetadataReportConfig metadataReportConfig) {
        addConfig(metadataReportConfig);
    }

    public void addMetadataReports(Iterable<MetadataReportConfig> metadataReportConfigs) {
        metadataReportConfigs.forEach(this::addMetadataReport);
    }

    public Collection<MetadataReportConfig> getMetadataConfigs() {
        return getConfigs(getTagName(MetadataReportConfig.class));
    }

    public Collection<MetadataReportConfig> getDefaultMetadataConfigs() {
        Collection<MetadataReportConfig> defaults = getDefaultConfigs(getConfigsMap(getTagName(MetadataReportConfig.class)));
        if (CollectionUtils.isEmpty(defaults)) {
            return getMetadataConfigs();
        }
        return defaults;
    }

    // ProtocolConfig correlative methods

    public void addProtocol(ProtocolConfig protocolConfig) {
        addConfig(protocolConfig);
    }

    public void addProtocols(Iterable<ProtocolConfig> protocolConfigs) {
        if (protocolConfigs != null) {
            protocolConfigs.forEach(this::addProtocol);
        }
    }

    public Optional<ProtocolConfig> getProtocol(String idOrName) {
        return getConfig(ProtocolConfig.class, idOrName);
    }

    public List<ProtocolConfig> getDefaultProtocols() {
        return getDefaultConfigs(ProtocolConfig.class);
    }

    @Override
    public <C extends AbstractConfig> List<C> getDefaultConfigs(Class<C> cls) {
        return getDefaultConfigs(getConfigsMap(getTagName(cls)));
    }

    public Collection<ProtocolConfig> getProtocols() {
        return getConfigs(getTagName(ProtocolConfig.class));
    }


    // RegistryConfig correlative methods

    public void addRegistry(RegistryConfig registryConfig) {
        addConfig(registryConfig);
    }

    public void addRegistries(Iterable<RegistryConfig> registryConfigs) {
        if (registryConfigs != null) {
            registryConfigs.forEach(this::addRegistry);
        }
    }

    public Optional<RegistryConfig> getRegistry(String id) {
        return getConfig(RegistryConfig.class, id);
    }

    public List<RegistryConfig> getDefaultRegistries() {
        return getDefaultConfigs(getConfigsMap(getTagName(RegistryConfig.class)));
    }

    public Collection<RegistryConfig> getRegistries() {
        return getConfigs(getTagName(RegistryConfig.class));
    }


    @Override
    public void refreshAll() {
        // refresh all configs here
        getApplication().ifPresent(ApplicationConfig::refresh);
        getMonitor().ifPresent(MonitorConfig::refresh);
        getMetrics().ifPresent(MetricsConfig::refresh);
        getSsl().ifPresent(SslConfig::refresh);

        getProtocols().forEach(ProtocolConfig::refresh);
        getRegistries().forEach(RegistryConfig::refresh);
        getConfigCenters().forEach(ConfigCenterConfig::refresh);
        getMetadataConfigs().forEach(MetadataReportConfig::refresh);
    }

    @Override
    public void loadConfigs() {
        // application config has load before starting config center
        // load dubbo.applications.xxx
        loadConfigsOfTypeFromProps(ApplicationConfig.class);

        // load dubbo.monitors.xxx
        loadConfigsOfTypeFromProps(MonitorConfig.class);

        // load dubbo.metrics.xxx
        loadConfigsOfTypeFromProps(MetricsConfig.class);

        // load multiple config types:
        // load dubbo.protocols.xxx
        loadConfigsOfTypeFromProps(ProtocolConfig.class);

        // load dubbo.registries.xxx
        loadConfigsOfTypeFromProps(RegistryConfig.class);

        // load dubbo.metadata-report.xxx
        loadConfigsOfTypeFromProps(MetadataReportConfig.class);

        // config centers has bean loaded before starting config center
        //loadConfigsOfTypeFromProps(ConfigCenterConfig.class);

        refreshAll();

        checkConfigs();

        // set model name
        if (StringUtils.isBlank(applicationModel.getModelName())) {
            applicationModel.setModelName(applicationModel.getApplicationName());
        }
    }

    private void checkConfigs() {
        // check config types (ignore metadata-center)
        List<Class<? extends AbstractConfig>> multipleConfigTypes = Arrays.asList(
            ApplicationConfig.class,
            ProtocolConfig.class,
            RegistryConfig.class,
            MetadataReportConfig.class,
            MonitorConfig.class,
            MetricsConfig.class,
            SslConfig.class);

        for (Class<? extends AbstractConfig> configType : multipleConfigTypes) {
            checkDefaultAndValidateConfigs(configType);
        }

        // check port conflicts
        Map<Integer, ProtocolConfig> protocolPortMap = new LinkedHashMap<>();
        for (ProtocolConfig protocol : this.getProtocols()) {
            Integer port = protocol.getPort();
            if (port == null || port == -1) {
                continue;
            }
            ProtocolConfig prevProtocol = protocolPortMap.get(port);
            if (prevProtocol != null) {
                throw new IllegalStateException("Duplicated port used by protocol configs, port: " + port +
                    ", configs: " + Arrays.asList(prevProtocol, protocol));
            }
            protocolPortMap.put(port, protocol);
        }
    }

    public ConfigMode getConfigMode() {
        return configMode;
    }
}
