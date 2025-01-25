/*
 * The MIT License
 *
 * Copyright (c) 2013 IKEDA Yasuyuki
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 * THE SOFTWARE.
 */

package org.jenkinsci.plugins.authorizeproject;

import edu.umd.cs.findbugs.annotations.CheckForNull;
import edu.umd.cs.findbugs.annotations.NonNull;
import hudson.BulkChange;
import hudson.DescriptorExtensionList;
import hudson.Extension;
import hudson.init.InitMilestone;
import hudson.init.Initializer;
import hudson.model.Action;
import hudson.model.Descriptor;
import hudson.model.DescriptorVisibilityFilter;
import hudson.model.Items;
import hudson.model.Job;
import hudson.model.JobProperty;
import hudson.model.JobPropertyDescriptor;
import hudson.model.Queue;
import hudson.util.FormApply;
import java.io.IOException;
import java.util.Collection;
import java.util.List;
import java.util.logging.Level;
import java.util.logging.Logger;
import javax.servlet.ServletException;
import jenkins.model.Jenkins;
import jenkins.model.TransientActionFactory;
import net.sf.json.JSONObject;
import org.acegisecurity.Authentication;
import org.jenkins.ui.icon.IconSpec;
import org.kohsuke.accmod.Restricted;
import org.kohsuke.accmod.restrictions.NoExternalUse;
import org.kohsuke.stapler.DataBoundConstructor;
import org.kohsuke.stapler.HttpResponse;
import org.kohsuke.stapler.StaplerRequest;
import org.kohsuke.stapler.interceptor.RequirePOST;

/**
 * Specifies how to authorize its builds.
 */
public class AuthorizeProjectProperty extends JobProperty<Job<?, ?>> {
    /**
     * Our logger.
     */
    private static final Logger LOGGER = Logger.getLogger(AuthorizeProjectProperty.class.getName());

    private AuthorizeProjectStrategy strategy;

    /**
     * Gets the strategy.
     *
     * @return the strategy.
     */
    public AuthorizeProjectStrategy getStrategy() {
        return strategy;
    }

    /**
     * Create a new instance.
     *
     * @param strategy the strategy
     */
    @DataBoundConstructor
    public AuthorizeProjectProperty(AuthorizeProjectStrategy strategy) {
        this.strategy = strategy;
    }

    /**
     * Gets the strategy if enabled or {@code null} if not enabled.
     *
     * @return strategy only when it's enabled. {@code null} otherwise.
     */
    @CheckForNull
    public AuthorizeProjectStrategy getEnabledStrategy() {
        AuthorizeProjectStrategy strategy = getStrategy();
        if (strategy == null) {
            return null;
        }
        if (DescriptorVisibilityFilter.apply(
                        ProjectQueueItemAuthenticator.getConfigured(), List.of(strategy.getDescriptor()))
                .isEmpty()) {
            LOGGER.log(
                    Level.WARNING,
                    "{0} is configured but disabled in the global-security configuration.",
                    strategy.getDescriptor().getDisplayName());
            return null;
        }
        return strategy;
    }

    /**
     * Return the authorization for a build.
     *
     * @param item the item in queue, which will be a build.
     * @return authorization for this build.
     * @see AuthorizeProjectStrategy#authenticate(hudson.model.Job, hudson.model.Queue.Item)
     */
    public Authentication authenticate(Queue.Item item) {
        AuthorizeProjectStrategy strategy = getEnabledStrategy();
        if (strategy == null) {
            return null;
        }
        return strategy.authenticate(owner, item);
    }

    /**
     * Ensure that deserialization failures in this field result in a failure to deserialize the job.
     * This method is responsible for ensuring that POSTing config.xml respects the defined strategy.
     */
    @Initializer(after = InitMilestone.PLUGINS_STARTED)
    public static void setStrategyCritical() {
        Items.XSTREAM2.addCriticalField(AuthorizeProjectProperty.class, "strategy");
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public JobProperty<?> reconfigure(StaplerRequest req, JSONObject form) throws Descriptor.FormException {
        // This is called when the job configuration is submitted.
        // authorize-project is preserved in job configuration pages.
        // It is updated via AuthorizationAction instead.
        return strategy != null && ProjectQueueItemAuthenticator.isConfigured() ? this : null;
    }

    /**
     * Descriptor for {@link AuthorizeProjectProperty}.
     * <p>
     * Provides functions for displaying.
     */
    @Extension
    public static class DescriptorImpl extends JobPropertyDescriptor {
        /**
         * @return the name shown in the project configuration page.
         * @see hudson.model.Descriptor#getDisplayName()
         */
        @Override
        public String getDisplayName() {
            return Messages.AuthorizeProjectProperty_DisplayName();
        }

        /**
         * Enabled only when {@link ProjectQueueItemAuthenticator} is configured.
         *
         * @param jobType the job type.
         * @return {@code true} if enabled for the specified job type.
         * @see hudson.model.JobPropertyDescriptor#isApplicable(java.lang.Class)
         */
        @SuppressWarnings("rawtypes")
        @Override
        public boolean isApplicable(Class<? extends Job> jobType) {
            return ProjectQueueItemAuthenticator.isConfigured();
        }

        /**
         * @return all the registered {@link AuthorizeProjectStrategy}.
         */
        @Deprecated
        public DescriptorExtensionList<AuthorizeProjectStrategy, Descriptor<AuthorizeProjectStrategy>>
                getStrategyList() {
            return AuthorizeProjectStrategy.all();
        }

        /**
         * @return enabled {@link AuthorizeProjectStrategy}, empty if authorize-project is not enabled.
         */
        public List<Descriptor<AuthorizeProjectStrategy>> getEnabledAuthorizeProjectStrategyDescriptorList() {
            ProjectQueueItemAuthenticator authenticator = ProjectQueueItemAuthenticator.getConfigured();
            if (authenticator == null) {
                return List.of();
            }
            return DescriptorVisibilityFilter.apply(authenticator, AuthorizeProjectStrategy.all());
        }
    }

    /**
     * The action that allows configuring a jobs authorization.
     *
     * @since 1.3.0
     */
    public static class AuthorizationAction implements Action, IconSpec {

        /**
         * The job that this action belongs to.
         */
        @NonNull
        private final Job<?, ?> job;

        /**
         * Constructor.
         *
         * @param job the job.
         */
        public AuthorizationAction(@NonNull Job<?, ?> job) {
            this.job = job;
        }

        /**
         * Gets the {@link AuthorizeProjectProperty}.
         *
         * @return the {@link AuthorizeProjectProperty}.
         */
        @Restricted(NoExternalUse.class) // mainly used by Jelly
        public AuthorizeProjectProperty getProperty() {
            return job.getProperty(AuthorizeProjectProperty.class);
        }

        /**
         * Gets the {@link AuthorizeProjectProperty.DescriptorImpl}
         *
         * @return the {@link AuthorizeProjectProperty.DescriptorImpl}
         */
        public DescriptorImpl getPropertyDescriptor() {
            return Jenkins.get().getDescriptorByType(DescriptorImpl.class);
        }

        @NonNull
        public Job<?, ?> getJob() {
            return job;
        }

        /**
         * {@inheritDoc}
         */
        @Override
        public String getIconFileName() {
            return ProjectQueueItemAuthenticator.isConfigured() ? "symbol-lock-closed" : null;
        }

        /**
         * {@inheritDoc}
         */
        @Override
        public String getDisplayName() {
            return Messages.AuthorizationAction_DisplayName();
        }

        /**
         * {@inheritDoc}
         */
        @Override
        public String getUrlName() {
            return "authorization";
        }

        /**
         * {@inheritDoc}
         */
        @Override
        public String getIconClassName() {
            return ProjectQueueItemAuthenticator.isConfigured() ? "symbol-lock-closed" : null;
        }

        /**
         * Handles the submission of the authorization configuration.
         * @param req the request.
         * @return the response.
         * @throws IOException when things go wrong.
         * @throws ServletException when things go wrong.
         */
        @RequirePOST
        @NonNull
        @Restricted(NoExternalUse.class)
        public synchronized HttpResponse doAuthorize(@NonNull StaplerRequest req) throws IOException, ServletException {
            job.checkPermission(Job.CONFIGURE);
            JSONObject json = req.getSubmittedForm();
            JSONObject o = json.optJSONObject(getPropertyDescriptor().getJsonSafeClassName());
            AuthorizeProjectProperty submitted = o != null ? req.bindJSON(AuthorizeProjectProperty.class, o) : null;
            // now it is safe to make the changes
            BulkChange bc = new BulkChange(job);
            try {
                AuthorizeProjectProperty existing = getProperty();
                if (existing != null) {
                    job.removeProperty(existing);
                }
                if (submitted != null) {
                    job.addProperty(submitted);
                }
                job.save();
                bc.commit();
                return FormApply.success("../");
            } catch (IOException e) {
                bc.abort();
                throw e;
            }
        }
    }

    /**
     * The action factory responsible for adding the {@link AuthorizationAction}.
     *
     * @since 1.3.0
     */
    @SuppressWarnings("rawtypes")
    @Extension(ordinal = Double.MAX_VALUE / 2) // close to the top
    public static class TransientActionFactoryImpl extends TransientActionFactory<Job> {

        /**
         * {@inheritDoc}
         */
        @Override
        public Class<Job> type() {
            return Job.class;
        }

        /**
         * {@inheritDoc}
         */
        @NonNull
        @Override
        public Collection<? extends Action> createFor(@NonNull Job target) {
            return List.of(new AuthorizationAction((Job<?, ?>) target));
        }
    }
}
