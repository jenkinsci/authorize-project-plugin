package org.jenkinsci.plugins.authorizeproject;

import hudson.Extension;
import hudson.model.Descriptor;
import hudson.model.Job;
import hudson.model.Queue;
import java.util.stream.Collectors;
import jenkins.security.QueueItemAuthenticator;
import jenkins.security.QueueItemAuthenticatorDescriptor;
import net.sf.json.JSONObject;
import org.jenkinsci.plugins.authorizeproject.strategy.AnonymousAuthorizationStrategy;
import org.kohsuke.stapler.DataBoundConstructor;
import org.kohsuke.stapler.StaplerRequest2;
import org.springframework.security.core.Authentication;

/**
 * A global default authenticator to allow changing the default for all projects.
 *
 * @since 1.2.0
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
    public Authentication authenticate2(Queue.Item item) {
        return strategy != null && item.task instanceof Job<?, ?> j ? strategy.authenticate(j, item) : null;
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

        /**
         * @return Descriptors for {@link AuthorizeProjectStrategy} applicable to {@link GlobalQueueItemAuthenticator}.
         */
        public Iterable<Descriptor<AuthorizeProjectStrategy>> getStrategyDescriptors() {
            return AuthorizeProjectStrategy.all().stream()
                    .filter(d -> {
                        if (!(d instanceof AuthorizeProjectStrategyDescriptor)) {
                            return true;
                        }
                        return ((AuthorizeProjectStrategyDescriptor) d).isApplicableToGlobal();
                    })
                    .collect(Collectors.toList());
        }

        public AuthorizeProjectStrategy getDefaultStrategy() {
            return new AnonymousAuthorizationStrategy();
        }

        /**
         * Creates new {@link GlobalQueueItemAuthenticator} from inputs.
         * This is required to call {@link hudson.model.Descriptor#newInstance(StaplerRequest2, JSONObject)}
         * of {@link AuthorizeProjectProperty}.
         *
         * @see hudson.model.Descriptor#newInstance(org.kohsuke.stapler.StaplerRequest2, net.sf.json.JSONObject)
         */
        @Override
        public GlobalQueueItemAuthenticator newInstance(StaplerRequest2 req, JSONObject formData) throws FormException {
            if (formData == null || formData.isNullObject()) {
                return null;
            }
            AuthorizeProjectStrategy strategy = AuthorizeProjectUtil.bindJSONWithDescriptor(
                    req, formData, "strategy", AuthorizeProjectStrategy.class);

            return new GlobalQueueItemAuthenticator(strategy);
        }
    }
}
