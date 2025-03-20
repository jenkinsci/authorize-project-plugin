package org.jenkinsci.plugins.authorizeproject;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.hasSize;
import static org.hamcrest.Matchers.instanceOf;

import hudson.util.DescribableList;
import io.jenkins.plugins.casc.ConfigurationContext;
import io.jenkins.plugins.casc.ConfiguratorRegistry;
import io.jenkins.plugins.casc.misc.ConfiguredWithCode;
import io.jenkins.plugins.casc.misc.JenkinsConfiguredWithCodeRule;
import io.jenkins.plugins.casc.misc.Util;
import io.jenkins.plugins.casc.misc.junit.jupiter.WithJenkinsConfiguredWithCode;
import io.jenkins.plugins.casc.model.CNode;
import java.util.Set;
import jenkins.security.QueueItemAuthenticator;
import jenkins.security.QueueItemAuthenticatorConfiguration;
import jenkins.security.QueueItemAuthenticatorDescriptor;
import org.jenkinsci.plugins.authorizeproject.strategy.AnonymousAuthorizationStrategy;
import org.jenkinsci.plugins.authorizeproject.strategy.SpecificUsersAuthorizationStrategy;
import org.jenkinsci.plugins.authorizeproject.strategy.SystemAuthorizationStrategy;
import org.jenkinsci.plugins.authorizeproject.strategy.TriggeringUsersAuthorizationStrategy;
import org.junit.jupiter.api.Test;

@WithJenkinsConfiguredWithCode
class ConfigurationAsCodeTest {

    @Test
    @ConfiguredWithCode("ConfigurationAsCodeTest/global.config.AnonymousAuthorizationStrategy.yml")
    void importGlobalAnonymousAuthorizationStrategy(JenkinsConfiguredWithCodeRule r) {
        DescribableList<QueueItemAuthenticator, QueueItemAuthenticatorDescriptor> authenticators =
                QueueItemAuthenticatorConfiguration.get().getAuthenticators();
        GlobalQueueItemAuthenticator queueItemAuthenticator = authenticators.get(GlobalQueueItemAuthenticator.class);

        assertThat(authenticators, hasSize(1));
        assertThat(queueItemAuthenticator.getStrategy(), instanceOf(AnonymousAuthorizationStrategy.class));
    }

    @Test
    @ConfiguredWithCode("ConfigurationAsCodeTest/global.config.AnonymousAuthorizationStrategy.yml")
    void exportGlobalAnonymousAuthorizationStrategy(JenkinsConfiguredWithCodeRule r) throws Exception {
        assertExport("ConfigurationAsCodeTest/global.export.AnonymousAuthorizationStrategy.yml");
    }

    @Test
    @ConfiguredWithCode("ConfigurationAsCodeTest/global.config.SpecificUsersAuthorizationStrategy.yml")
    void importGlobalSpecificUsersAuthorizationStrategy(JenkinsConfiguredWithCodeRule r) {
        DescribableList<QueueItemAuthenticator, QueueItemAuthenticatorDescriptor> authenticators =
                QueueItemAuthenticatorConfiguration.get().getAuthenticators();
        GlobalQueueItemAuthenticator queueItemAuthenticator = authenticators.get(GlobalQueueItemAuthenticator.class);

        assertThat(authenticators, hasSize(1));
        assertThat(queueItemAuthenticator.getStrategy(), instanceOf(SpecificUsersAuthorizationStrategy.class));
        assertThat(
                ((SpecificUsersAuthorizationStrategy) queueItemAuthenticator.getStrategy()).getUserid(),
                equalTo("some-user"));
    }

    @Test
    @ConfiguredWithCode("ConfigurationAsCodeTest/global.config.SpecificUsersAuthorizationStrategy.yml")
    void exportGlobalSpecificUsersAuthorizationStrategy(JenkinsConfiguredWithCodeRule r) throws Exception {
        assertExport("ConfigurationAsCodeTest/global.export.SpecificUsersAuthorizationStrategy.yml");
    }

    @Test
    @ConfiguredWithCode("ConfigurationAsCodeTest/global.config.SystemAuthorizationStrategy.yml")
    void importGlobalSystemAuthorizationStrategy(JenkinsConfiguredWithCodeRule r) {
        DescribableList<QueueItemAuthenticator, QueueItemAuthenticatorDescriptor> authenticators =
                QueueItemAuthenticatorConfiguration.get().getAuthenticators();
        GlobalQueueItemAuthenticator queueItemAuthenticator = authenticators.get(GlobalQueueItemAuthenticator.class);

        assertThat(authenticators, hasSize(1));
        assertThat(queueItemAuthenticator.getStrategy(), instanceOf(SystemAuthorizationStrategy.class));
    }

    @Test
    @ConfiguredWithCode("ConfigurationAsCodeTest/global.config.SystemAuthorizationStrategy.yml")
    void exportGlobalSystemAuthorizationStrategy(JenkinsConfiguredWithCodeRule r) throws Exception {
        assertExport("ConfigurationAsCodeTest/global.export.SystemAuthorizationStrategy.yml");
    }

    @Test
    @ConfiguredWithCode("ConfigurationAsCodeTest/global.config.TriggeringUsersAuthorizationStrategy.yml")
    void importGlobalTriggeringUsersAuthorizationStrategy(JenkinsConfiguredWithCodeRule r) {
        DescribableList<QueueItemAuthenticator, QueueItemAuthenticatorDescriptor> authenticators =
                QueueItemAuthenticatorConfiguration.get().getAuthenticators();
        GlobalQueueItemAuthenticator queueItemAuthenticator = authenticators.get(GlobalQueueItemAuthenticator.class);

        assertThat(authenticators, hasSize(1));
        assertThat(queueItemAuthenticator.getStrategy(), instanceOf(TriggeringUsersAuthorizationStrategy.class));
    }

    @Test
    @ConfiguredWithCode("ConfigurationAsCodeTest/global.config.TriggeringUsersAuthorizationStrategy.yml")
    void exportGlobalTriggeringUsersAuthorizationStrategy(JenkinsConfiguredWithCodeRule r) throws Exception {
        assertExport("ConfigurationAsCodeTest/global.export.TriggeringUsersAuthorizationStrategy.yml");
    }

    @Test
    @ConfiguredWithCode("ConfigurationAsCodeTest/project.config.all.yml")
    void importProjectTriggeringUsersAuthorizationStrategy(JenkinsConfiguredWithCodeRule r) {
        DescribableList<QueueItemAuthenticator, QueueItemAuthenticatorDescriptor> authenticators =
                QueueItemAuthenticatorConfiguration.get().getAuthenticators();
        ProjectQueueItemAuthenticator queueItemAuthenticator = authenticators.get(ProjectQueueItemAuthenticator.class);

        assertThat(authenticators, hasSize(1));
        assertThat(
                queueItemAuthenticator.getDisabledStrategies(),
                equalTo(Set.of(
                        SystemAuthorizationStrategy.class.getName(),
                        SpecificUsersAuthorizationStrategy.class.getName(),
                        TriggeringUsersAuthorizationStrategy.class.getName())));
        assertThat(
                queueItemAuthenticator.getEnabledStrategies(),
                equalTo(Set.of(AnonymousAuthorizationStrategy.class.getName())));
    }

    @Test
    @ConfiguredWithCode("ConfigurationAsCodeTest/project.config.all.yml")
    void exportProjectTriggeringUsersAuthorizationStrategy(JenkinsConfiguredWithCodeRule r) throws Exception {
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
}
