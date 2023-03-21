package org.jenkinsci.plugins.authorizeproject;

import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.hasSize;
import static org.hamcrest.Matchers.instanceOf;
import static org.junit.Assert.assertThat;

import hudson.util.DescribableList;
import io.jenkins.plugins.casc.ConfigurationContext;
import io.jenkins.plugins.casc.ConfiguratorRegistry;
import io.jenkins.plugins.casc.misc.ConfiguredWithCode;
import io.jenkins.plugins.casc.misc.JenkinsConfiguredWithCodeRule;
import io.jenkins.plugins.casc.misc.Util;
import io.jenkins.plugins.casc.model.CNode;
import java.util.Arrays;
import java.util.HashSet;
import jenkins.security.QueueItemAuthenticator;
import jenkins.security.QueueItemAuthenticatorConfiguration;
import jenkins.security.QueueItemAuthenticatorDescriptor;
import org.jenkinsci.plugins.authorizeproject.strategy.AnonymousAuthorizationStrategy;
import org.jenkinsci.plugins.authorizeproject.strategy.SpecificUsersAuthorizationStrategy;
import org.jenkinsci.plugins.authorizeproject.strategy.SystemAuthorizationStrategy;
import org.jenkinsci.plugins.authorizeproject.strategy.TriggeringUsersAuthorizationStrategy;
import org.junit.Rule;
import org.junit.Test;
import org.jvnet.hudson.test.recipes.LocalData;

public class ConfigurationAsCodeTest {

    @Rule public JenkinsConfiguredWithCodeRule r = new JenkinsConfiguredWithCodeRule();

    @Test
    @ConfiguredWithCode("ConfigurationAsCodeTest/global.config.AnonymousAuthorizationStrategy.yml")
    public void importGlobalAnonymousAuthorizationStrategy() {
        DescribableList<QueueItemAuthenticator, QueueItemAuthenticatorDescriptor> authenticators = QueueItemAuthenticatorConfiguration.get().getAuthenticators();
        GlobalQueueItemAuthenticator queueItemAuthenticator = authenticators.get(GlobalQueueItemAuthenticator.class);

        assertThat(authenticators, hasSize(1));
        assertThat(queueItemAuthenticator.getStrategy(), instanceOf(AnonymousAuthorizationStrategy.class));
    }

    @Test
    @ConfiguredWithCode("ConfigurationAsCodeTest/global.config.AnonymousAuthorizationStrategy.yml")
    public void exportGlobalAnonymousAuthorizationStrategy() throws Exception {
        assertExport("ConfigurationAsCodeTest/global.export.AnonymousAuthorizationStrategy.yml");
    }

    @Test
    @ConfiguredWithCode("ConfigurationAsCodeTest/global.config.SpecificUsersAuthorizationStrategy.yml")
    public void importGlobalSpecificUsersAuthorizationStrategy() {
        DescribableList<QueueItemAuthenticator, QueueItemAuthenticatorDescriptor> authenticators = QueueItemAuthenticatorConfiguration.get().getAuthenticators();
        GlobalQueueItemAuthenticator queueItemAuthenticator = authenticators.get(GlobalQueueItemAuthenticator.class);

        assertThat(authenticators, hasSize(1));
        assertThat(queueItemAuthenticator.getStrategy(), instanceOf(SpecificUsersAuthorizationStrategy.class));
        assertThat(((SpecificUsersAuthorizationStrategy) queueItemAuthenticator.getStrategy()).getUserid(), equalTo("some-user"));
    }

    @Test
    @ConfiguredWithCode("ConfigurationAsCodeTest/global.config.SpecificUsersAuthorizationStrategy.yml")
    public void exportGlobalSpecificUsersAuthorizationStrategy() throws Exception {
        assertExport("ConfigurationAsCodeTest/global.export.SpecificUsersAuthorizationStrategy.yml");
    }

    @Test
    @ConfiguredWithCode("ConfigurationAsCodeTest/global.config.SystemAuthorizationStrategy.yml")
    public void importGlobalSystemAuthorizationStrategy() {
        DescribableList<QueueItemAuthenticator, QueueItemAuthenticatorDescriptor> authenticators = QueueItemAuthenticatorConfiguration.get().getAuthenticators();
        GlobalQueueItemAuthenticator queueItemAuthenticator = authenticators.get(GlobalQueueItemAuthenticator.class);

        assertThat(authenticators, hasSize(1));
        assertThat(queueItemAuthenticator.getStrategy(), instanceOf(SystemAuthorizationStrategy.class));
    }

    @Test
    @ConfiguredWithCode("ConfigurationAsCodeTest/global.config.SystemAuthorizationStrategy.yml")
    public void exportGlobalSystemAuthorizationStrategy() throws Exception {
        assertExport("ConfigurationAsCodeTest/global.export.SystemAuthorizationStrategy.yml");
    }

    @Test
    @ConfiguredWithCode("ConfigurationAsCodeTest/global.config.TriggeringUsersAuthorizationStrategy.yml")
    public void importGlobalTriggeringUsersAuthorizationStrategy() {
        DescribableList<QueueItemAuthenticator, QueueItemAuthenticatorDescriptor> authenticators = QueueItemAuthenticatorConfiguration.get().getAuthenticators();
        GlobalQueueItemAuthenticator queueItemAuthenticator = authenticators.get(GlobalQueueItemAuthenticator.class);

        assertThat(authenticators, hasSize(1));
        assertThat(queueItemAuthenticator.getStrategy(), instanceOf(TriggeringUsersAuthorizationStrategy.class));
    }

    @Test
    @ConfiguredWithCode("ConfigurationAsCodeTest/global.config.TriggeringUsersAuthorizationStrategy.yml")
    public void exportGlobalTriggeringUsersAuthorizationStrategy() throws Exception {
        assertExport("ConfigurationAsCodeTest/global.export.TriggeringUsersAuthorizationStrategy.yml");
    }

    @Test
    @ConfiguredWithCode("ConfigurationAsCodeTest/project.config.all.yml")
    public void importProjectTriggeringUsersAuthorizationStrategy() {
        DescribableList<QueueItemAuthenticator, QueueItemAuthenticatorDescriptor> authenticators = QueueItemAuthenticatorConfiguration.get().getAuthenticators();
        ProjectQueueItemAuthenticator queueItemAuthenticator = authenticators.get(ProjectQueueItemAuthenticator.class);

        assertThat(authenticators, hasSize(1));
        assertThat(queueItemAuthenticator.getDisabledStrategies(), equalTo(new HashSet<>(Arrays.asList("org.jenkinsci.plugins.authorizeproject.strategy.SystemAuthorizationStrategy", "org.jenkinsci.plugins.authorizeproject.strategy.SpecificUsersAuthorizationStrategy", "org.jenkinsci.plugins.authorizeproject.strategy.TriggeringUsersAuthorizationStrategy"))));
        assertThat(queueItemAuthenticator.getEnabledStrategies(), equalTo(new HashSet<>(Arrays.asList("org.jenkinsci.plugins.authorizeproject.strategy.AnonymousAuthorizationStrategy"))));
    }

    @Test
    @ConfiguredWithCode("ConfigurationAsCodeTest/project.config.all.yml")
    public void exportProjectTriggeringUsersAuthorizationStrategy() throws Exception {
        assertExport("ConfigurationAsCodeTest/project.export.all.yml");
    }

    private void assertExport(String resourcePath) throws Exception {
        ConfiguratorRegistry registry = ConfiguratorRegistry.get();
        ConfigurationContext context = new ConfigurationContext(registry);
        CNode queueItemAuthenticator = Util.getSecurityRoot(context).get("queueItemAuthenticator");

        String exported = Util.toYamlString(queueItemAuthenticator);
        String expected = Util.toStringFromYamlFile(this, resourcePath);

        assertThat(exported, equalTo(expected));
    }

    @LocalData
    @Test
    public void strategyEnabledMapMigration() {
        DescribableList<QueueItemAuthenticator, QueueItemAuthenticatorDescriptor> authenticators = QueueItemAuthenticatorConfiguration.get().getAuthenticators();
        ProjectQueueItemAuthenticator queueItemAuthenticator = authenticators.get(ProjectQueueItemAuthenticator.class);

        assertThat(authenticators, hasSize(1));
        assertThat(queueItemAuthenticator.getDisabledStrategies(), equalTo(new HashSet<>(Arrays.asList(SpecificUsersAuthorizationStrategy.class.getName(), SystemAuthorizationStrategy.class.getName()))));
        assertThat(queueItemAuthenticator.getEnabledStrategies(), equalTo(new HashSet<>(Arrays.asList(AnonymousAuthorizationStrategy.class.getName(), TriggeringUsersAuthorizationStrategy.class.getName()))));
    }
}
