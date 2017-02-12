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

package org.jenkinsci.plugins.authorizeproject.strategy;

import hudson.Extension;
import hudson.model.Job;
import hudson.model.Queue;
import hudson.model.User;
import hudson.security.ACL;
import hudson.security.AbstractPasswordBasedSecurityRealm;
import hudson.security.AccessControlled;
import hudson.security.SecurityRealm;
import hudson.util.FormValidation;

import java.io.ObjectStreamException;
import java.util.Collections;
import java.util.logging.Level;
import java.util.logging.Logger;
import jenkins.model.Jenkins;
import jenkins.security.ApiTokenProperty;
import net.sf.json.JSONObject;
import org.acegisecurity.AccessDeniedException;
import org.acegisecurity.Authentication;
import org.acegisecurity.providers.UsernamePasswordAuthenticationToken;
import org.acegisecurity.userdetails.UsernameNotFoundException;
import org.apache.commons.lang.StringUtils;
import org.jenkinsci.plugins.authorizeproject.AuthorizeProjectProperty;
import org.jenkinsci.plugins.authorizeproject.AuthorizeProjectStrategy;
import org.jenkinsci.plugins.authorizeproject.AuthorizeProjectStrategyDescriptor;
import org.jenkinsci.plugins.authorizeproject.AuthorizeProjectUtil;
import org.kohsuke.accmod.Restricted;
import org.kohsuke.accmod.restrictions.NoExternalUse;
import org.kohsuke.stapler.DataBoundConstructor;
import org.kohsuke.stapler.DataBoundSetter;
import org.kohsuke.stapler.QueryParameter;
import org.kohsuke.stapler.StaplerRequest;

/**
 * Run builds as a user specified in project configuration pages.
 */
public class SpecificUsersAuthorizationStrategy extends AuthorizeProjectStrategy {
    private static Logger LOGGER = Logger.getLogger(SpecificUsersAuthorizationStrategy.class.getName());
    private final String userid;
    
    private final static Authentication[] BUILTIN_USERS = {
            ACL.SYSTEM,
            Jenkins.ANONYMOUS,
    };
    
    /**
     * @return id of the user to run builds as.
     */
    public String getUserid() {
        return userid;
    }

    // to migrate from < 1.3.0.
    private transient Boolean noNeedReauthentication;

    private boolean dontRestrictJobConfiguration;

    /**
     * @return whether not to restrict job configuration
     * @see #hasJobConfigurePermission(AccessControlled)
     * @since 1.3.0
     */
    public boolean isDontRestrictJobConfiguration() {
        return dontRestrictJobConfiguration;
    }

    /**
     * @param dontRestrictPermission whether not to restrict job configuration
     * @see #hasJobConfigurePermission(AccessControlled)
     * @since 1.3.0
     */
    @DataBoundSetter
    public void setDontRestrictJobConfiguration(boolean dontRestrictPermission) {
        this.dontRestrictJobConfiguration = dontRestrictPermission;
    }

    public SpecificUsersAuthorizationStrategy(String userid) {
        this.userid = StringUtils.trim(userid);
        this.dontRestrictJobConfiguration = false;
        for (Authentication a : BUILTIN_USERS) {
            if (AuthorizeProjectUtil.userIdEquals(this.userid, a.getPrincipal().toString())) {
                throw new IllegalArgumentException(Messages.SpecificUsersAuthorizationStrategy_userid_builtin());
            }
        }
    }

    /**
     * No {@link DataBoundConstructor} for requiring to pass the authentication.
     *
     * authentication is performed in {@link DescriptorImpl#newInstance(StaplerRequest, JSONObject)}
     */
    @DataBoundConstructor
    public SpecificUsersAuthorizationStrategy(String userid, boolean useApitoken,
                                              String apitoken, String password) throws AccessDeniedException {
        this(userid);
        if (isAuthenticationRequired(getUserid()) && !authenticate(getUserid(), useApitoken, apitoken, password)) {
            throw new AccessDeniedException(Messages.SpecificUsersAuthorizationStrategy_userid_authenticate());
        }
    }

    static boolean authenticate(String userId, boolean useApitoken, String apitoken, String password) {
        if (useApitoken) {
            if (apitoken != null) {
                User u = User.get(userId, false, Collections.emptyMap());
                if (u != null) {
                    ApiTokenProperty p = u.getProperty(ApiTokenProperty.class);
                    if (p != null && p.matchesPassword(apitoken)) {
                        // supplied API token matches
                        return true;
                    }
                }
            }
        } else {
            if (password != null) {
                try {
                    Jenkins.getActiveInstance().getSecurityRealm().getSecurityComponents().manager.authenticate(
                            new UsernamePasswordAuthenticationToken(userId, password)
                    );
                    // supplied password matches
                    return true;
                } catch (Exception e) { // handles any exception including NPE.
                    LOGGER.log(Level.WARNING, String.format("Failed to authenticate %s", userId), e);
                }
            }
        }
        return false;
    }

    protected static boolean isAuthenticationRequired(String userId) {
        if (Jenkins.getActiveInstance().hasPermission(Jenkins.ADMINISTER)) {
            // Administrator can specify any user.
            return false;
        }

        User u = User.current();
        if (u != null && AuthorizeProjectUtil.userIdEquals(u.getId(), userId)) {
            // Any user can specify oneself.
            return false;
        }
        return true;
    }

    @Override
    public DescriptorImpl getDescriptor() {
        return (DescriptorImpl) super.getDescriptor();
    }

    /**
     * Run builds as a specified user.
     * 
     * If the user is invalid, run as anonymous.
     * 
     * @param project
     * @param item
     * @return
     * @see org.jenkinsci.plugins.authorizeproject.AuthorizeProjectStrategy#authenticate(hudson.model.Job, hudson.model.Queue.Item)
     */
    @Override
    public Authentication authenticate(Job<?, ?> project, Queue.Item item) {
        User u = User.get(getUserid(), false, Collections.emptyMap());
        if (u == null) {
            // fallback to anonymous
            return Jenkins.ANONYMOUS;
        }
        try {
            Authentication a = u.impersonate();
            return a;
        } catch (UsernameNotFoundException e) {
            LOGGER.log(Level.WARNING, String.format("Invalid User %s. Falls back to anonymous.", getUserid()), e);
            return Jenkins.ANONYMOUS;
        }
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public boolean hasJobConfigurePermission(AccessControlled context) {
        if (isDontRestrictJobConfiguration()) {
            return true;
        }
        return AuthorizeProjectUtil.userIdEquals(Jenkins.getAuthentication().getName(), userid);
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public boolean hasAuthorizationConfigurePermission(AccessControlled context) {
        return !isAuthenticationRequired(getUserid());
    }

    /**
     * Return {@link SpecificUsersAuthorizationStrategy} configured in a project.
     * 
     * @param project
     * @return
     */
    protected static SpecificUsersAuthorizationStrategy getCurrentStrategy(Job<?,?> project) {
        if (project == null) {
            return null;
        }
        
        AuthorizeProjectProperty prop = project.getProperty(AuthorizeProjectProperty.class);
        if (prop == null) {
            return null;
        }
        
        if (!(prop.getStrategy() instanceof SpecificUsersAuthorizationStrategy)) {
            return null;
        }
        
        return (SpecificUsersAuthorizationStrategy)prop.getStrategy();
    }
    
    /**
     * {@inheritDoc}
     */
    @Override
    protected Object readResolve() throws ObjectStreamException {
        SpecificUsersAuthorizationStrategy self = (SpecificUsersAuthorizationStrategy)super.readResolve();
        if (self.noNeedReauthentication != null) {
            self.setDontRestrictJobConfiguration(self.noNeedReauthentication.booleanValue());
        }
        return self;
    }

    /**
     * Our descriptor.
     */
    @Extension
    public static class DescriptorImpl extends AuthorizeProjectStrategyDescriptor {

        /**
         * {@inheritDoc}
         */
        @Override
        public String getDisplayName() {
            return Messages.SpecificUsersAuthorizationStrategy_DisplayName();
        }
        
        /**
         * Helper method for computing the check password URL.
         *
         * @return the URL to check password field is required.
         */
        @Restricted(NoExternalUse.class) // used by stapler/jelly
        @SuppressWarnings("unused")
        public String calcCheckPasswordRequestedUrl() {
            return String.format("'%s/%s/checkPasswordRequested' + qs(this).nearBy('userid')",
                    getCurrentDescriptorByNameUrl(),
                    getDescriptorUrl()
            );
        }
        
        /**
         * Checks password field is required in configuration page.
         * 
         * This is called asynchronously.
         * 
         * @param req the request.
         * @param userid the userid.
         * @return "true" if password fiels is required. this should be evaluated as JavaScript.
         */
        @Restricted(NoExternalUse.class) // used by stapler/jelly
        @SuppressWarnings("unused")
        public String doCheckPasswordRequested(StaplerRequest req, @QueryParameter String userid) {
            return Boolean.toString(isAuthenticationRequired(userid.trim()));
        }
        
        /**
         * Checks the userid against the blacklist of invalid users.
         * @param userid the userid
         * @return the validation results.
         */
        @Restricted(NoExternalUse.class) // used by stapler/jelly
        @SuppressWarnings("unused")
        public FormValidation doCheckUserid(@QueryParameter String userid) {
            if (StringUtils.isBlank(userid)) {
                return FormValidation.error(Messages.SpecificUsersAuthorizationStrategy_userid_required());
            }
            for (Authentication a: BUILTIN_USERS) {
                if (AuthorizeProjectUtil.userIdEquals(userid, a.getPrincipal().toString())) {
                    return FormValidation.error(Messages.SpecificUsersAuthorizationStrategy_userid_builtin());
                }
            }
            return FormValidation.ok();
        }
        
        /**
         * Checks the supplied password.
         *
         * @param req the request.
         * @param userid the user id.
         * @param password the password.
         * @return the validationr results,
         */
        @Restricted(NoExternalUse.class) // used by stapler/jelly
        @SuppressWarnings("unused")
        public FormValidation doCheckPassword(
                StaplerRequest req,
                @QueryParameter String userid,
                @QueryParameter String password,
                @QueryParameter String apitoken,
                @QueryParameter boolean useApitoken
        ) {
            if (!isAuthenticationRequired(userid.trim())) {
                // authentication is not required.
                return FormValidation.ok();
            }
            
            if (useApitoken ? StringUtils.isBlank(apitoken) : StringUtils.isBlank(password)) {
                return FormValidation.error(Messages.SpecificUsersAuthorizationStrategy_password_required());
            }
            
            return FormValidation.ok();
        }

        /**
         * Display warnings for {@code dontRestrictJobConfiguration}
         *
         * "Don't restrict job configuration" can cause security issues
         * when used with inappropriate access controls,
         * and display for a waning message for that.
         *
         * @param dontRestrictJobConfiguration whether not to restrict job configuration
         * @return a warning message for {@code dontRestrictJobConfiguration} if it is {@code true}
         * @see SpecificUsersAuthorizationStrategy#setDontRestrictJobConfiguration(boolean)
         */
        public FormValidation doCheckDontRestrictJobConfiguration(@QueryParameter boolean dontRestrictJobConfiguration) {
            if (dontRestrictJobConfiguration) {
                return FormValidation.warning(Messages.SpecificUsersAuthorizationStrategy_dontRestrictJobConfiguration_usage());
            }
            return FormValidation.ok();
        }

        /**
         * Checks if the current {@link SecurityRealm} supports username/password authentication.
         *
         * @return {@code true} if and only if the current realm supports username/password authentication.
         */
        @Restricted(NoExternalUse.class) // used by stapler/jelly
        @SuppressWarnings("unused")
        public boolean isUseApitoken() {
            return !(Jenkins.getActiveInstance().getSecurityRealm() instanceof AbstractPasswordBasedSecurityRealm);
        }
        
        /**
         * {@link SpecificUsersAuthorizationStrategy} should be disabled by default for JENKINS-28298
         * @return false
         * @see org.jenkinsci.plugins.authorizeproject.AuthorizeProjectStrategyDescriptor#isEnabledByDefault()
         */
        @Override
        public boolean isEnabledByDefault() {
            return false;
        }
    }
}
