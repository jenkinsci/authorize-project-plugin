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

import static org.junit.Assert.*;
import jenkins.model.Jenkins;
import hudson.model.FreeStyleProject;
import hudson.model.ParametersDefinitionProperty;
import hudson.model.StringParameterDefinition;
import hudson.model.User;
import hudson.security.ACL;

import org.jenkinsci.plugins.authorizeproject.AuthorizeProjectProperty;
import org.jenkinsci.plugins.authorizeproject.testutil.AuthorizationCheckBuilder;
import org.jenkinsci.plugins.authorizeproject.testutil.AuthorizeProjectJenkinsRule;
import org.junit.Rule;
import org.junit.Test;
import org.jvnet.hudson.test.JenkinsRule;
import org.jvnet.hudson.test.recipes.LocalData;

/**
 *
 */
public class SpecificUsersAuthorizationStrategyTest {
    @Rule
    public JenkinsRule j = new AuthorizeProjectJenkinsRule();
    
    @Test
    @LocalData
    public void testIsAuthenticateionRequiredAsUser() {
        ACL.impersonate(User.get("test1").impersonate());
        assertFalse(Jenkins.getInstance().hasPermission(Jenkins.ADMINISTER));
        // after: not configured
        // before: test2, require re-auth
        // result: false
        assertFalse(SpecificUsersAuthorizationStrategy.isAuthenticateionRequired(
                null,
                new SpecificUsersAuthorizationStrategy("test2", false)
        ));
        
        // after: test1, require re-auth
        // before: test2, require re-auth
        // result: false
        assertFalse(SpecificUsersAuthorizationStrategy.isAuthenticateionRequired(
                new SpecificUsersAuthorizationStrategy("test1", false),
                new SpecificUsersAuthorizationStrategy("test2", false)
        ));
        
        // after: test1, require re-auth
        // before: not configured
        // result: false
        assertFalse(SpecificUsersAuthorizationStrategy.isAuthenticateionRequired(
                new SpecificUsersAuthorizationStrategy("test1", false),
                null
        ));
        
        // after: test2, no require re-auth
        // before: not configured
        // result: true
        assertTrue(SpecificUsersAuthorizationStrategy.isAuthenticateionRequired(
                new SpecificUsersAuthorizationStrategy("test2", true),
                null
        ));
        
        // after: test2, require re-auth
        // before: test2, no require re-auth
        // result: false
        assertFalse(SpecificUsersAuthorizationStrategy.isAuthenticateionRequired(
                new SpecificUsersAuthorizationStrategy("test2", false),
                new SpecificUsersAuthorizationStrategy("test2", true)
        ));
        
        // after: admin, no require re-auth
        // before: test2, no require re-auth
        // result: true
        assertTrue(SpecificUsersAuthorizationStrategy.isAuthenticateionRequired(
                new SpecificUsersAuthorizationStrategy("admin", true),
                new SpecificUsersAuthorizationStrategy("test2", true)
        ));
        
        
        // after: null, no require re-auth
        // before: null, no require re-auth
        // result: anything (not ABEND)
        SpecificUsersAuthorizationStrategy.isAuthenticateionRequired(
                new SpecificUsersAuthorizationStrategy(null, true),
                new SpecificUsersAuthorizationStrategy(null, true)
        );
    }
    
    @Test
    @LocalData
    public void testIsAuthenticateionRequiredAsAdministrator() {
        ACL.impersonate(User.get("admin").impersonate());
        assertTrue(Jenkins.getInstance().hasPermission(Jenkins.ADMINISTER));
        // after: not configured
        // before: test2, require re-auth
        // result: false
        assertFalse(SpecificUsersAuthorizationStrategy.isAuthenticateionRequired(
                null,
                new SpecificUsersAuthorizationStrategy("test2", false)
        ));
        
        // after: test1, require re-auth
        // before: test2, require re-auth
        // result: false
        assertFalse(SpecificUsersAuthorizationStrategy.isAuthenticateionRequired(
                new SpecificUsersAuthorizationStrategy("test1", false),
                new SpecificUsersAuthorizationStrategy("test2", false)
        ));
        
        // after: test1, require re-auth
        // before: not configured
        // result: false
        assertFalse(SpecificUsersAuthorizationStrategy.isAuthenticateionRequired(
                new SpecificUsersAuthorizationStrategy("test1", false),
                null
        ));
        
        // after: test2, no require re-auth
        // before: not configured
        // result: false
        assertFalse(SpecificUsersAuthorizationStrategy.isAuthenticateionRequired(
                new SpecificUsersAuthorizationStrategy("test2", true),
                null
        ));
        
        // after: test2, require re-auth
        // before: test2, no require re-auth
        // result: false
        assertFalse(SpecificUsersAuthorizationStrategy.isAuthenticateionRequired(
                new SpecificUsersAuthorizationStrategy("test2", false),
                new SpecificUsersAuthorizationStrategy("test2", true)
        ));
        
        // after: admin, no require re-auth
        // before: test2, no require re-auth
        // result: false
        assertFalse(SpecificUsersAuthorizationStrategy.isAuthenticateionRequired(
                new SpecificUsersAuthorizationStrategy("admin", true),
                new SpecificUsersAuthorizationStrategy("test2", true)
        ));
        
        
        // after: null, no require re-auth
        // before: null, no require re-auth
        // result: anything (not ABEND)
        SpecificUsersAuthorizationStrategy.isAuthenticateionRequired(
                new SpecificUsersAuthorizationStrategy(null, true),
                new SpecificUsersAuthorizationStrategy(null, true)
        );
    }
    
    @Test
    @LocalData
    public void testIsAuthenticateionRequiredAnonymous() {
        ACL.impersonate(Jenkins.ANONYMOUS);
        assertFalse(Jenkins.getInstance().hasPermission(Jenkins.ADMINISTER));
        // after: not configured
        // before: test2, require re-auth
        // result: false
        assertFalse(SpecificUsersAuthorizationStrategy.isAuthenticateionRequired(
                null,
                new SpecificUsersAuthorizationStrategy("test2", false)
        ));
        
        // after: test1, require re-auth
        // before: test2, require re-auth
        // result: true
        assertTrue(SpecificUsersAuthorizationStrategy.isAuthenticateionRequired(
                new SpecificUsersAuthorizationStrategy("test1", false),
                new SpecificUsersAuthorizationStrategy("test2", false)
        ));
        
        // after: test1, require re-auth
        // before: not configured
        // result: true
        assertTrue(SpecificUsersAuthorizationStrategy.isAuthenticateionRequired(
                new SpecificUsersAuthorizationStrategy("test1", false),
                null
        ));
        
        // after: test2, no require re-auth
        // before: not configured
        // result: true
        assertTrue(SpecificUsersAuthorizationStrategy.isAuthenticateionRequired(
                new SpecificUsersAuthorizationStrategy("test2", true),
                null
        ));
        
        // after: test2, require re-auth
        // before: test2, no require re-auth
        // result: false
        assertFalse(SpecificUsersAuthorizationStrategy.isAuthenticateionRequired(
                new SpecificUsersAuthorizationStrategy("test2", false),
                new SpecificUsersAuthorizationStrategy("test2", true)
        ));
        
        // after: admin, no require re-auth
        // before: test2, no require re-auth
        // result: true
        assertTrue(SpecificUsersAuthorizationStrategy.isAuthenticateionRequired(
                new SpecificUsersAuthorizationStrategy("admin", true),
                new SpecificUsersAuthorizationStrategy("test2", true)
        ));
        
        
        // after: null, no require re-auth
        // before: null, no require re-auth
        // result: anything (not ABEND)
        SpecificUsersAuthorizationStrategy.isAuthenticateionRequired(
                new SpecificUsersAuthorizationStrategy(null, true),
                new SpecificUsersAuthorizationStrategy(null, true)
        );
    }
    
    @Test
    public void testGetCurrentStrategy() throws Exception {
        {
            assertNull(SpecificUsersAuthorizationStrategy.getCurrentStrategy(null));
        }
        {
            FreeStyleProject p = j.createFreeStyleProject();
            assertNull(SpecificUsersAuthorizationStrategy.getCurrentStrategy(p));
        }
        {
            FreeStyleProject p = j.createFreeStyleProject();
            p.addProperty(new ParametersDefinitionProperty(new StringParameterDefinition("foo", "bar")));
            assertNull(SpecificUsersAuthorizationStrategy.getCurrentStrategy(p));
        }
        {
            FreeStyleProject p = j.createFreeStyleProject();
            p.addProperty(new AuthorizeProjectProperty(null));
            assertNull(SpecificUsersAuthorizationStrategy.getCurrentStrategy(p));
        }
        {
            FreeStyleProject p = j.createFreeStyleProject();
            p.addProperty(new AuthorizeProjectProperty(new AnonymousAuthorizationStrategy()));
            assertNull(SpecificUsersAuthorizationStrategy.getCurrentStrategy(p));
        }
        {
            String userid = "foo";
            boolean noNeedReauthentication = true;
            FreeStyleProject p = j.createFreeStyleProject();
            p.addProperty(new ParametersDefinitionProperty(new StringParameterDefinition("foo", "bar")));
            p.addProperty(new AuthorizeProjectProperty(new SpecificUsersAuthorizationStrategy(userid, noNeedReauthentication)));
            SpecificUsersAuthorizationStrategy s = SpecificUsersAuthorizationStrategy.getCurrentStrategy(p);
            assertNotNull(p);
            assertEquals(userid, s.getUserid());
            assertEquals(noNeedReauthentication, s.isNoNeedReauthentication());
        }
    }
    
    private static class AuthenticateDescriptorImpl extends SpecificUsersAuthorizationStrategy.DescriptorImpl {
        public AuthenticateDescriptorImpl() {
            super(SpecificUsersAuthorizationStrategy.class);
        }
        
        @Override
        public boolean authenticate(
                SpecificUsersAuthorizationStrategy strategy,
                String password
        ) {
            return super.authenticate(strategy, password);
        }
    }
    
    @Test
    @LocalData
    public void testDescriptorAuthenticate() throws Exception {
        AuthenticateDescriptorImpl d = new AuthenticateDescriptorImpl();
        assertTrue(d.authenticate(new SpecificUsersAuthorizationStrategy("test1", false), "test1"));
        assertFalse(d.authenticate(new SpecificUsersAuthorizationStrategy("test1", false), "test2"));
        assertFalse(d.authenticate(new SpecificUsersAuthorizationStrategy("test1", false), ""));
        assertFalse(d.authenticate(new SpecificUsersAuthorizationStrategy("", false), "test2"));
        assertFalse(d.authenticate(new SpecificUsersAuthorizationStrategy("test1", false), null));
        assertFalse(d.authenticate(new SpecificUsersAuthorizationStrategy(null, false), "test2"));
    }
    
    @Test
    @LocalData
    public void testAuthenticate() throws Exception {
        // if not configured, run in SYSTEM privilege.
        {
            FreeStyleProject p = j.createFreeStyleProject();
            AuthorizationCheckBuilder checker = new AuthorizationCheckBuilder();
            p.getBuildersList().add(checker);
            
            j.assertBuildStatusSuccess(p.scheduleBuild2(0));
            assertEquals(ACL.SYSTEM, checker.authentication);
        }
        
        // if configured, run in specified user.
        {
            FreeStyleProject p = j.createFreeStyleProject();
            AuthorizationCheckBuilder checker = new AuthorizationCheckBuilder();
            p.getBuildersList().add(checker);
            
            p.addProperty(new AuthorizeProjectProperty(new SpecificUsersAuthorizationStrategy("test1", false)));
            
            j.assertBuildStatusSuccess(p.scheduleBuild2(0));
            assertEquals("test1", checker.authentication.getName());
        }
        
        // if configured, run in specified user.
        {
            FreeStyleProject p = j.createFreeStyleProject();
            AuthorizationCheckBuilder checker = new AuthorizationCheckBuilder();
            p.getBuildersList().add(checker);
            
            p.addProperty(new AuthorizeProjectProperty(new SpecificUsersAuthorizationStrategy("admin", false)));
            
            j.assertBuildStatusSuccess(p.scheduleBuild2(0));
            assertEquals("admin", checker.authentication.getName());
        }
        
        // invalid user
        {
            FreeStyleProject p = j.createFreeStyleProject();
            AuthorizationCheckBuilder checker = new AuthorizationCheckBuilder();
            p.getBuildersList().add(checker);
            
            p.addProperty(new AuthorizeProjectProperty(new SpecificUsersAuthorizationStrategy("nosuchuser", false)));
            
            j.assertBuildStatusSuccess(p.scheduleBuild2(0));
            assertEquals(Jenkins.ANONYMOUS, checker.authentication);
        }
        
        // null
        // it highly depends on its implementation how SecurityRealm works
        // for invalid input, so this test may fail when the implementation of 
        // SecurityReam changed.
        {
            FreeStyleProject p = j.createFreeStyleProject();
            AuthorizationCheckBuilder checker = new AuthorizationCheckBuilder();
            p.getBuildersList().add(checker);
            
            p.addProperty(new AuthorizeProjectProperty(new SpecificUsersAuthorizationStrategy(null, false)));
            
            j.assertBuildStatusSuccess(p.scheduleBuild2(0));
            assertEquals(Jenkins.ANONYMOUS, checker.authentication);
        }
    }
}
