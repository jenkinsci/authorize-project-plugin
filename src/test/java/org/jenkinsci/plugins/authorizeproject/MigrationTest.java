package org.jenkinsci.plugins.authorizeproject;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.hasSize;

import hudson.util.DescribableList;
import java.util.Set;
import jenkins.security.QueueItemAuthenticator;
import jenkins.security.QueueItemAuthenticatorConfiguration;
import jenkins.security.QueueItemAuthenticatorDescriptor;
import org.jenkinsci.plugins.authorizeproject.strategy.AnonymousAuthorizationStrategy;
import org.jenkinsci.plugins.authorizeproject.strategy.SpecificUsersAuthorizationStrategy;
import org.jenkinsci.plugins.authorizeproject.strategy.SystemAuthorizationStrategy;
import org.jenkinsci.plugins.authorizeproject.strategy.TriggeringUsersAuthorizationStrategy;
import org.junit.jupiter.api.Test;
import org.jvnet.hudson.test.JenkinsRule;
import org.jvnet.hudson.test.junit.jupiter.WithJenkins;
import org.jvnet.hudson.test.recipes.LocalData;

@WithJenkins
class MigrationTest {

    @LocalData
    @Test
    void strategyEnabledMapMigration(JenkinsRule r) {
        DescribableList<QueueItemAuthenticator, QueueItemAuthenticatorDescriptor> authenticators =
                QueueItemAuthenticatorConfiguration.get().getAuthenticators();
        ProjectQueueItemAuthenticator queueItemAuthenticator = authenticators.get(ProjectQueueItemAuthenticator.class);

        assertThat(authenticators, hasSize(1));
        assertThat(
                queueItemAuthenticator.getDisabledStrategies(),
                equalTo(Set.of(
                        SpecificUsersAuthorizationStrategy.class.getName(),
                        SystemAuthorizationStrategy.class.getName())));
        assertThat(
                queueItemAuthenticator.getEnabledStrategies(),
                equalTo(Set.of(
                        AnonymousAuthorizationStrategy.class.getName(),
                        TriggeringUsersAuthorizationStrategy.class.getName())));
    }
}
