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

import java.io.IOException;
import java.util.Collections;
import java.util.logging.Level;
import java.util.logging.Logger;

import jenkins.model.Jenkins;
import jenkins.security.ApiTokenProperty;
import hudson.Extension;
import hudson.model.Queue;
import hudson.model.User;
import hudson.model.AbstractProject;
import hudson.model.Descriptor;
import hudson.model.Job;
import hudson.security.ACL;
import hudson.security.AbstractPasswordBasedSecurityRealm;
import hudson.util.FormValidation;
import net.sf.json.JSONObject;

import org.acegisecurity.Authentication;
import org.acegisecurity.providers.UsernamePasswordAuthenticationToken;
import org.apache.commons.lang.StringUtils;
import org.jenkinsci.plugins.authorizeproject.AuthorizeProjectStrategy;
import org.jenkinsci.plugins.authorizeproject.AuthorizeProjectStrategyDescriptor;
import org.jenkinsci.plugins.authorizeproject.AuthorizeProjectProperty;
import org.jenkinsci.plugins.authorizeproject.AuthorizeProjectUtil;
import org.kohsuke.stapler.DataBoundConstructor;
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
    
    private final boolean noNeedReauthentication;
    
    /**
     * @return if true, entering password is not required when the userid is not changed.
     */
    public boolean isNoNeedReauthentication() {
        return noNeedReauthentication;
    }
    
    /**
     * No {@link DataBoundConstructor} for requiring to pass the authentication.
     * 
     * authentication is performed in {@link DescriptorImpl#newInstance(StaplerRequest, JSONObject)}
     */
    public SpecificUsersAuthorizationStrategy(String userid, boolean noNeedReauthentication) {
        this.userid = StringUtils.trim(userid);
        this.noNeedReauthentication = noNeedReauthentication;
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
        Authentication a = u.impersonate();
        if (a == null) {
            // fallback to anonymous
            return Jenkins.ANONYMOUS;
        }
        return a;
    }
    
    /**
     * Returns whether authentication is required to update the configuration to newStrategy.
     * 
     * @param newStrategy strategy to be configured.
     * @param currentStrategy strategy now configured.
     * @return whether authentication is required.
     */
    protected static boolean isAuthenticateionRequired(
            SpecificUsersAuthorizationStrategy newStrategy,
            SpecificUsersAuthorizationStrategy currentStrategy
    ) {
        if (newStrategy == null) {
            // if configure is removed, no need to authenticate.
            return false;
        }
        
        if (Jenkins.getInstance().hasPermission(Jenkins.ADMINISTER)) {
            // Administrator can specify any user.
            return false;
        }
        
        User u = User.current();
        if (u != null && u.getId() != null && AuthorizeProjectUtil.userIdEquals(u.getId(), newStrategy.getUserid())) {
            // Any user can specify oneself.
            return false;
        }
        
        if (currentStrategy == null) {
            // if currentStrategy is null, authentication is always required.
            return true;
        }

        if (
                currentStrategy.isNoNeedReauthentication()
                && currentStrategy.getUserid() != null
                && AuthorizeProjectUtil.userIdEquals(currentStrategy.getUserid(), newStrategy.getUserid())
        ) {
            // the specified user is not changed, 
            // and specified that authentication is not required in that case.
            return false;
        }
        
        return true;
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
    
    @Deprecated
    protected static SpecificUsersAuthorizationStrategy getCurrentStrategy(AbstractProject<?,?> project) {
        return getCurrentStrategy((Job<?,?>)project);
    }
    
    /**
     * Called when XSTREAM2 instantiates this from XML configuration.
     * 
     * When configured via REST/CLI, {@link Descriptor#newInstance(StaplerRequest, JSONObject)} is not called.
     * Instead checks authentication here.
     * 
     * @return return myself.
     * @throws IOException authentication failed.
     */
    private Object readResolve() throws IOException {
        if (!ACL.SYSTEM.equals(Jenkins.getAuthentication())) {
            // This is called via REST/CLI.
            
            // There's no way to retrieve current strategy.
            if (isAuthenticateionRequired(this, null)) {
                // As REST/CLI interface saves configuration after successfully load object from the XML,
                // this prevents the new configuration saved.
                throw new IOException(Messages.SpecificUsersAuthorizationStrategy_userid_readResolve());
            }
        }
        return this;
    }
    
    /**
     *
     */
    @Extension
    public static class DescriptorImpl extends AuthorizeProjectStrategyDescriptor {
        /**
         * 
         */
        public DescriptorImpl() {
            super();
        }
        
        /**
         * For testing purpose.
         * 
         * @param clazz set SpecificUsersAuthorizationStrategy.class
         */
        protected DescriptorImpl(Class<? extends AuthorizeProjectStrategy> clazz) {
            super(clazz);
        }
        
        /**
         * @return the name shown in project configuration pages.
         * @see hudson.model.Descriptor#getDisplayName()
         */
        @Override
        public String getDisplayName() {
            return Messages.SpecificUsersAuthorizationStrategy_DisplayName();
        }
        
        /**
         * Create a new instance. No authentication is performed.
         * 
         * @param req
         * @param formData
         * @return
         * @throws FormException thrown when the input is incomplete.
         */
        protected SpecificUsersAuthorizationStrategy newInstanceWithoutAuthentication(
                StaplerRequest req,
                JSONObject formData
        ) throws FormException {
            String userid = formData.getString("userid");
            boolean noNeedReauthentication = formData.getBoolean("noNeedReauthentication");
            
            if (StringUtils.isBlank(userid)) {
                throw new FormException("userid must be specified", "userid");
            }
            for (Authentication a: BUILTIN_USERS) {
                if (AuthorizeProjectUtil.userIdEquals(userid, a.getPrincipal().toString())) {
                    throw new FormException(Messages.SpecificUsersAuthorizationStrategy_userid_builtin(), "userid");
                }
            }

            return new SpecificUsersAuthorizationStrategy(
                    userid, 
                    noNeedReauthentication
            );
        }
        
        /**
         * Authenticate the specified user.
         * 
         * Checks whether the user has privilege to specify that authorization.
         * 
         * @param strategy
         * @param password
         * @return true if the authentication is succeeded.
         */
        protected boolean authenticate(
                SpecificUsersAuthorizationStrategy strategy, 
                String password
        ) {
            try {
                Jenkins.getInstance().getSecurityRealm().getSecurityComponents().manager.authenticate(
                        new UsernamePasswordAuthenticationToken(strategy.getUserid(), password)
                );
            } catch (Exception e) { // handles any exception including NPE.
                LOGGER.log(Level.WARNING, String.format("Failed to authenticate %s", strategy.userid), e);
                return false;
            }
            return true;
        }
        
        /**
         * Authenticate the specified user with Apitoken.
         * 
         * @param strategy
         * @param apitoken
         * @return true if the authentication is succeeded.
         */
        protected boolean authenticateWithApitoken(
                SpecificUsersAuthorizationStrategy strategy, 
                String apitoken
        ) {
            User u = User.get(strategy.getUserid(), false, Collections.emptyMap());
            if (u == null) {
                return false;
            }
            ApiTokenProperty p = u.getProperty(ApiTokenProperty.class);
            if (p == null) {
                return false;
            }
            return p.matchesPassword(apitoken);
        }
        
        /**
         * Authenticate the specified user.
         * 
         * Checks whether the user has privilege to specify that authorization.
         * 
         * @param strategy
         * @param req
         * @param formData
         * @return true if the authentication is succeeded.
         */
        protected boolean authenticate(
                SpecificUsersAuthorizationStrategy strategy, 
                StaplerRequest req,
                JSONObject formData
        ) {
            boolean useApitoken = formData.optBoolean("useApitoken");
            
            return useApitoken
                    ?authenticateWithApitoken(strategy, formData.getString("apitoken"))
                    :authenticate(strategy, formData.getString("password"));
        }
        
        /**
         * Create a new instance. Also performs authentication.
         * 
         * @param req
         * @param formData
         * @return
         * @throws FormException thrown when the input is incomplete, or authentication failed.
         */
        @Override
        public SpecificUsersAuthorizationStrategy newInstance(StaplerRequest req, JSONObject formData)
                throws FormException {
            SpecificUsersAuthorizationStrategy strategy = newInstanceWithoutAuthentication(req, formData);
            
            SpecificUsersAuthorizationStrategy currentStrategy
                = getCurrentStrategy(req.findAncestorObject(Job.class));
            
            if (isAuthenticateionRequired(strategy, currentStrategy)) {
                if (!authenticate(strategy, req, formData)) {
                    throw new FormException(Messages.SpecificUsersAuthorizationStrategy_userid_authenticate(), "userid");
                }
            }
            
            return strategy;
        }
        
        /**
         * @return the URL to check password field is required.
         */
        public String calcCheckPasswordRequestedUrl() {
            return String.format("'%s/%s/checkPasswordRequested' + qs(this).nearBy('userid').nearBy('noNeedReauthentication')",
                    getCurrentDescriptorByNameUrl(),
                    getDescriptorUrl()
            );
        }
        
        /**
         * Checks password field is required in configuration page.
         * 
         * This is called asynchronously.
         * 
         * @param req
         * @param userid
         * @param noNeedReauthentication
         * @return "true" if password fiels is required. this should be evaluated as JavaScript.
         */
        public String doCheckPasswordRequested(
                StaplerRequest req,
                @QueryParameter String userid,
                @QueryParameter boolean noNeedReauthentication
        ) {
            SpecificUsersAuthorizationStrategy newStrategy = new SpecificUsersAuthorizationStrategy(userid, noNeedReauthentication);
            return Boolean.toString(isAuthenticateionRequired(
                    newStrategy,
                    getCurrentStrategy(req.findAncestorObject(Job.class))
            ));
        }
        
        /**
         * @param userid
         * @return
         */
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
         * @param req
         * @param userid
         * @param password
         * @param noNeedReauthentication
         * @return
         */
        public FormValidation doCheckPassword(
                StaplerRequest req,
                @QueryParameter String userid,
                @QueryParameter String password,
                @QueryParameter String apitoken,
                @QueryParameter boolean useApitoken,
                @QueryParameter boolean noNeedReauthentication
        ) {
            SpecificUsersAuthorizationStrategy newStrategy = new SpecificUsersAuthorizationStrategy(userid, noNeedReauthentication);
            if (!isAuthenticateionRequired(
                    newStrategy,
                    getCurrentStrategy(req.findAncestorObject(Job.class))
            )) {
                // authentication is not required.
                return FormValidation.ok();
            }
            
            if (
                    (!useApitoken && StringUtils.isBlank(password))
                    || (useApitoken && StringUtils.isBlank(apitoken))
            ) {
                return FormValidation.error(Messages.SpecificUsersAuthorizationStrategy_password_required());
            }
            
            /* Authentication should not be performed here,
             * for this may cause account locking or
             * is used for brute force attack.
             * Authentication is done only in saving the configuration
             * (that is, in DescriptorImpl#newInstance)
            if (
                    (!useApitoken && !authenticate(newStrategy, password))
                    (useApitoken && authenticateWithApitoken(newStrategy, apitoken))
            ) {
                return FormValidation.error(Messages.SpecificUsersAuthorizationStrategy_password_invalid());
            }
            */
            
            return FormValidation.ok();
        }
        
        /**
         * @param noNeedReauthentication
         * @return
         */
        public FormValidation doCheckNoNeedReauthentication(@QueryParameter boolean noNeedReauthentication) {
            if (noNeedReauthentication) {
                return FormValidation.warning(Messages.SpecificUsersAuthorizationStrategy_noNeedReauthentication_usage());
            }
            return FormValidation.ok();
        }
        
        public boolean isUseApitoken() {
            return !(Jenkins.getInstance().getSecurityRealm() instanceof AbstractPasswordBasedSecurityRealm);
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
