package org.jenkinsci.plugins.authorizeproject;

import hudson.Extension;
import hudson.model.Job;
import hudson.model.Queue;
import jenkins.security.QueueItemAuthenticator;
import jenkins.security.QueueItemAuthenticatorDescriptor;
import org.acegisecurity.Authentication;
import org.jenkinsci.plugins.authorizeproject.strategy.AnonymousAuthorizationStrategy;
import org.kohsuke.stapler.DataBoundConstructor;

/**
 * A global default authenticator to allow changing the default for all projects.
 *
 * @since 1.1.1
 */
public class GlobalQueueItemAuthenticator extends QueueItemAuthenticator {
    private final AuthorizeProjectStrategy strategy;

    @DataBoundConstructor
    public GlobalQueueItemAuthenticator(AuthorizeProjectStrategy strategy) {
        this.strategy = strategy;
    }

    public AuthorizeProjectStrategy getStrategy() {
        return strategy;
    }

    @Override
    public Authentication authenticate(Queue.Item item) {
        return strategy != null && item.task instanceof Job ? strategy.authenticate((Job<?, ?>) item.task, item) : null;
    }

    @Extension
    public static class DescriptorImpl extends QueueItemAuthenticatorDescriptor {
        /**
         * {@inheritDoc}
         */
        @Override
        public String getDisplayName() {
            return Messages.GlobalQueueItemAuthenticator_DisplayName();
        }

        public AuthorizeProjectStrategy getDefaultStrategy() {
            return new AnonymousAuthorizationStrategy();
        }
    }
}
