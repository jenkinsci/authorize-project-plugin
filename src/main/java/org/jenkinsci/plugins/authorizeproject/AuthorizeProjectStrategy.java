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

import hudson.DescriptorExtensionList;
import hudson.ExtensionPoint;
import hudson.Util;
import hudson.model.AbstractDescribableImpl;
import hudson.model.AbstractProject;
import hudson.model.Descriptor;
import hudson.model.Job;
import hudson.model.Queue;
import hudson.security.ACL;
import hudson.security.AccessControlled;
import java.io.InvalidObjectException;
import java.io.ObjectStreamException;
import java.util.logging.Level;
import java.util.logging.Logger;
import jenkins.model.Jenkins;
import org.acegisecurity.AccessDeniedException;
import org.acegisecurity.Authentication;
import org.kohsuke.stapler.Stapler;
import org.kohsuke.stapler.StaplerRequest;

/**
 * Extension point to define a new strategy to authorize builds configured in project configuration pages.
 */
public abstract class AuthorizeProjectStrategy extends AbstractDescribableImpl<AuthorizeProjectStrategy>
        implements ExtensionPoint {
    private static final Logger LOGGER = Logger.getLogger(AuthorizeProjectStrategy.class.getName());
    /**
     * @return all the registered {@link AuthorizeProjectStrategy}.
     */
    public static DescriptorExtensionList<AuthorizeProjectStrategy, Descriptor<AuthorizeProjectStrategy>> all() {
        return Jenkins.get().getDescriptorList(AuthorizeProjectStrategy.class);
    }

    /**
     * Returns the {@link Authentication} for the build.
     *
     * @param project the project to run.
     * @param item the item in queue, which will be a build.
     * @return {@code true} if authentication was successful
     */
    public Authentication authenticate(Job<?, ?> project, Queue.Item item) {
        if (!Util.isOverridden(
                AuthorizeProjectStrategy.class, getClass(), "authenticate", AbstractProject.class, Queue.Item.class)) {
            throw new AbstractMethodError();
        }

        if (!(project instanceof AbstractProject)) {
            Descriptor<?> d = Jenkins.get().getDescriptor(getClass());
            LOGGER.log(
                    Level.WARNING,
                    "This authorization strategy ({0}) is designed for authorize-project < 1.1.0 and not applicable for non-AbstractProjects (like WorkflowJob). ignored.",
                    (d != null) ? d.getDisplayName() : getClass().getName());
            return null;
        }
        return authenticate((AbstractProject<?, ?>) project, item);
    }

    /**
     * Old {@link AbstractProject} based version of {@link #authenticate(Job, Queue.Item)}.
     *
     * @param project the project to run.
     * @param item the item in queue, which will be a build.
     * @return {@code true} if authentication was successful
     * @deprecated use {@link #authenticate(hudson.model.Job, Queue.Item)} instead.
     */
    @Deprecated
    public Authentication authenticate(AbstractProject<?, ?> project, Queue.Item item) {
        return authenticate((Job<?, ?>) project, item);
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public AuthorizeProjectStrategyDescriptor getDescriptor() {
        return (AuthorizeProjectStrategyDescriptor) super.getDescriptor();
    }

    /**
     * Checks that the job can be reconfigured by the current user when this strategy is the configured strategy.
     *
     * @param context the context of the job
     * @throws AccessDeniedException if the current user is not allowed to reconfigure the specified job
     * @since 1.3.0
     */
    public final void checkJobConfigurePermission(AccessControlled context) {
        if (!hasJobConfigurePermission(context)) {
            throw new AccessDeniedException(Messages.AuthorizeProjectStrategy_UserNotAuthorizedForJob(
                    Jenkins.getAuthentication().getName()));
        }
    }

    /**
     * Tests if the job can be reconfigured by the current user when this strategy is the configured strategy.
     * Users with {@link Jenkins#ADMINISTER} permission skips this check.
     *
     * @param context the context of the job
     * @return {@code true} if and only if the current user is allowed to reconfigure the specified job.
     * @since 1.3.0
     */
    public boolean hasJobConfigurePermission(AccessControlled context) {
        return true;
    }

    /**
     * Checks that the authorization can be configured by the current user.
     *
     * @param context the context of the job
     * @throws AccessDeniedException if the current user is not allowed to configure this authorization
     * @since 1.3.0
     */
    public final void checkAuthorizationConfigurePermission(AccessControlled context) {
        if (!hasAuthorizationConfigurePermission(context)) {
            throw new AccessDeniedException(Messages.AuthorizeProjectStrategy_UserNotAuthorized(
                    Jenkins.getAuthentication().getName()));
        }
    }

    /**
     * Tests if the authorization can be configured by the current user.
     * Users with {@link Jenkins#ADMINISTER} permission skips this check.
     *
     * @param context the context of the job
     * @return {@code true} if and only if the current user is allowed to configure this authorization.
     * @since 1.3.0
     */
    public boolean hasAuthorizationConfigurePermission(AccessControlled context) {
        return true;
    }

    /**
     * If we are being deserialized outside of loading the initial jobs (or reloading) then we need to cross check
     * the strategy permissions to defend against somebody trying to push a configuration relating to a user other
     * than themselves.
     *
     * @return {@code this}
     * @throws ObjectStreamException if the object cannot be deserialized.
     * @see AuthorizeProjectProperty#setStrategyCritical()
     */
    protected Object readResolve() throws ObjectStreamException {
        checkUnsecuredConfiguration();
        return this;
    }

    private void checkUnsecuredConfiguration() throws ObjectStreamException {
        Authentication authentication = Jenkins.getAuthentication();
        if (authentication == ACL.SYSTEM) {
            // It is considered to initial loading or reloading.
            return;
        }
        if (!ProjectQueueItemAuthenticator.isConfigured()) {
            return;
        }
        if (Jenkins.get().hasPermission(Jenkins.ADMINISTER)) {
            // allows any configurations by system administrators.
            // It may not be allowed even if the user is an administrator of the job.
            return;
        }
        StaplerRequest request = Stapler.getCurrentRequest();
        AccessControlled context = (request != null) ? request.findAncestorObject(AccessControlled.class) : null;
        if (context == null) {
            context = Jenkins.get();
        }
        if (!hasJobConfigurePermission(context)) {
            String name = Jenkins.getAuthentication().getName();
            String userNotAuthorizedForJob = Messages.AuthorizeProjectStrategy_UserNotAuthorizedForJob(name);
            throw new InvalidObjectException(userNotAuthorizedForJob);
        }
        if (!hasAuthorizationConfigurePermission(context)) {
            String name = Jenkins.getAuthentication().getName();
            String userNotAuthorized = Messages.AuthorizeProjectStrategy_UserNotAuthorized(name);
            throw new InvalidObjectException(userNotAuthorized);
        }
    }
}
