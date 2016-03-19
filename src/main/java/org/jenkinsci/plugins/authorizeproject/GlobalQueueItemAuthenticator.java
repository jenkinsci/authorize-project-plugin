package org.jenkinsci.plugins.authorizeproject;

import hudson.Extension;
import hudson.model.Descriptor;
import hudson.model.Job;
import hudson.model.Queue;
import jenkins.security.QueueItemAuthenticator;
import jenkins.security.QueueItemAuthenticatorDescriptor;
import net.sf.json.JSONObject;

import org.acegisecurity.Authentication;
import org.jenkinsci.plugins.authorizeproject.strategy.AnonymousAuthorizationStrategy;
import org.kohsuke.stapler.DataBoundConstructor;
import org.kohsuke.stapler.StaplerRequest;

import com.google.common.base.Predicate;
import com.google.common.collect.Iterables;

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

        /**
         * @return Descriptors for {@link AuthorizeProjectStrategy} applicable to {@link GlobalQueueItemAuthenticator}.
         */
        public Iterable<Descriptor<AuthorizeProjectStrategy>> getStrategyDescriptors() {
            return Iterables.filter(
                    AuthorizeProjectStrategy.all(),
                    new Predicate<Descriptor<AuthorizeProjectStrategy>>() {
                        public boolean apply(Descriptor<AuthorizeProjectStrategy> d) {
                            if (!(d instanceof AuthorizeProjectStrategyDescriptor)) {
                                return true;
                            }
                            return ((AuthorizeProjectStrategyDescriptor)d).isApplicableToGlobal();
                        }
                    }
            );
        }

        public AuthorizeProjectStrategy getDefaultStrategy() {
            return new AnonymousAuthorizationStrategy();
        }

        /**
         * Creates new {@link GlobalQueueItemAuthenticator} from inputs.
         * This is required to call {@link hudson.model.Descriptor#newInstance(StaplerRequest, JSONObject)}
         * of {@link AuthorizeProjectProperty}.
         * 
         * @param req
         * @param formData
         * @return
         * @throws hudson.model.Descriptor.FormException
         * @see hudson.model.Descriptor#newInstance(org.kohsuke.stapler.StaplerRequest, net.sf.json.JSONObject)
         */
        @Override
        public GlobalQueueItemAuthenticator newInstance(StaplerRequest req, JSONObject formData)
                throws FormException
        {
            if(formData == null || formData.isNullObject()) {
                return null;
            }
            AuthorizeProjectStrategy strategy = AuthorizeProjectUtil.bindJSONWithDescriptor(req, formData, "strategy", AuthorizeProjectStrategy.class);
            
            return new GlobalQueueItemAuthenticator(strategy);
        }
    }
}
