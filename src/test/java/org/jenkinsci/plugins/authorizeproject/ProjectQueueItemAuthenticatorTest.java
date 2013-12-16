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

import static org.junit.Assert.*;
import jenkins.model.Jenkins;
import hudson.matrix.AxisList;
import hudson.matrix.MatrixProject;
import hudson.matrix.TextAxis;
import hudson.model.AbstractProject;
import hudson.model.Descriptor;
import hudson.model.FreeStyleProject;
import hudson.model.Queue;
import hudson.security.ACL;
import net.sf.json.JSONObject;

import org.acegisecurity.Authentication;
import org.jenkinsci.plugins.authorizeproject.strategy.AnonymousAuthorizationStrategy;
import org.jenkinsci.plugins.authorizeproject.testutil.AuthorizationCheckBuilder;
import org.jenkinsci.plugins.authorizeproject.testutil.AuthorizeProjectJenkinsRule;
import org.junit.Rule;
import org.junit.Test;
import org.jvnet.hudson.test.JenkinsRule;
import org.jvnet.hudson.test.JenkinsRule.WebClient;
import org.jvnet.hudson.test.TestExtension;
import org.kohsuke.stapler.StaplerRequest;

import com.gargoylesoftware.htmlunit.html.HtmlForm;
import com.gargoylesoftware.htmlunit.html.HtmlPage;
import com.gargoylesoftware.htmlunit.html.HtmlTextInput;

/**
 *
 */
public class ProjectQueueItemAuthenticatorTest {
    @Rule
    public JenkinsRule j = new AuthorizeProjectJenkinsRule();
    
    public static class NullAuthorizeProjectStrategy extends AuthorizeProjectStrategy {
        @Override
        public Authentication authenticate(AbstractProject<?, ?> project, Queue.Item item) {
            return null;
        }
    }
    
    @Test
    public void testWorkForFreeStyleProject() throws Exception {
        // if not configured, run in SYSTEM privilege.
        {
            FreeStyleProject p = j.createFreeStyleProject();
            AuthorizationCheckBuilder checker = new AuthorizationCheckBuilder();
            p.getBuildersList().add(checker);
            
            j.assertBuildStatusSuccess(p.scheduleBuild2(0));
            assertEquals(ACL.SYSTEM, checker.authentication);
        }
        
        // if configured, AuthorizeProjectStrategy takes effect
        {
            FreeStyleProject p = j.createFreeStyleProject();
            AuthorizationCheckBuilder checker = new AuthorizationCheckBuilder();
            p.getBuildersList().add(checker);
            
            p.addProperty(new AuthorizeProjectProperty(new AnonymousAuthorizationStrategy()));
            
            j.assertBuildStatusSuccess(p.scheduleBuild2(0));
            assertEquals(Jenkins.ANONYMOUS, checker.authentication);
        }
        
        // if configured wrong, run in SYSTEM privilege.
        {
            FreeStyleProject p = j.createFreeStyleProject();
            AuthorizationCheckBuilder checker = new AuthorizationCheckBuilder();
            p.getBuildersList().add(checker);
            
            p.addProperty(new AuthorizeProjectProperty(null));
            
            j.assertBuildStatusSuccess(p.scheduleBuild2(0));
            assertEquals(ACL.SYSTEM, checker.authentication);
        }
        
        // if the strategy returns null, run in SYSTEM privilege.
        {
            FreeStyleProject p = j.createFreeStyleProject();
            AuthorizationCheckBuilder checker = new AuthorizationCheckBuilder();
            p.getBuildersList().add(checker);
            
            p.addProperty(new AuthorizeProjectProperty(new NullAuthorizeProjectStrategy()));
            
            j.assertBuildStatusSuccess(p.scheduleBuild2(0));
            assertEquals(ACL.SYSTEM, checker.authentication);
        }
    }
    
    @Test
    public void testWorkForMatrixProject() throws Exception {
        // if not configured, run in SYSTEM privilege.
        {
            MatrixProject p = j.createMatrixProject();
            p.setAxes(new AxisList(new TextAxis("axis1", "value1")));
            AuthorizationCheckBuilder checker = new AuthorizationCheckBuilder();
            p.getBuildersList().add(checker);
            
            j.assertBuildStatusSuccess(p.scheduleBuild2(0));
            assertEquals(ACL.SYSTEM, checker.authentication);
        }
        
        // if configured, AuthorizeProjectStrategy takes effect
        {
            MatrixProject p = j.createMatrixProject();
            p.setAxes(new AxisList(new TextAxis("axis1", "value1")));
            AuthorizationCheckBuilder checker = new AuthorizationCheckBuilder();
            p.getBuildersList().add(checker);
            
            p.addProperty(new AuthorizeProjectProperty(new AnonymousAuthorizationStrategy()));
            
            j.assertBuildStatusSuccess(p.scheduleBuild2(0));
            assertEquals(Jenkins.ANONYMOUS, checker.authentication);
        }
        
        // if configured wrong, run in SYSTEM privilege.
        {
            MatrixProject p = j.createMatrixProject();
            p.setAxes(new AxisList(new TextAxis("axis1", "value1")));
            AuthorizationCheckBuilder checker = new AuthorizationCheckBuilder();
            p.getBuildersList().add(checker);
            
            p.addProperty(new AuthorizeProjectProperty(null));
            
            j.assertBuildStatusSuccess(p.scheduleBuild2(0));
            assertEquals(ACL.SYSTEM, checker.authentication);
        }
        
        // if the strategy returns null, run in SYSTEM privilege.
        {
            MatrixProject p = j.createMatrixProject();
            p.setAxes(new AxisList(new TextAxis("axis1", "value1")));
            AuthorizationCheckBuilder checker = new AuthorizationCheckBuilder();
            p.getBuildersList().add(checker);
            
            p.addProperty(new AuthorizeProjectProperty(new NullAuthorizeProjectStrategy()));
            
            j.assertBuildStatusSuccess(p.scheduleBuild2(0));
            assertEquals(ACL.SYSTEM, checker.authentication);
        }
    }
    
    /**
     * Test no exception even if AuthorizeProjectStrategyDescriptor is not used.
     */
    public static class AuthorizeProjectStrategyExtendingBaseDescrptor extends AuthorizeProjectStrategy {
        @Override
        public Authentication authenticate(AbstractProject<?, ?> project, Queue.Item item) {
            return null;
        }
        
        @TestExtension("testGlobalSecurityConfiguration")
        public static class DescriptorImpl extends Descriptor<AuthorizeProjectStrategy> {
            @Override
            public String getDisplayName() {
                return "AuthorizeProjectStrategyExtendingBaseDescrptor";
            }
        }
    }
    
    /**
     * Test no exception even if no global-security.jelly is not provided.
     */
    public static class AuthorizeProjectStrategyWithoutGlobalSecurityConfiguration extends AuthorizeProjectStrategy {
        @Override
        public Authentication authenticate(AbstractProject<?, ?> project, Queue.Item item) {
            return null;
        }
        
        @TestExtension("testGlobalSecurityConfiguration")
        public static class DescriptorImpl extends AuthorizeProjectStrategyDescriptor {
            @Override
            public String getDisplayName() {
                return "AuthorizeProjectStrategyWithoutGlobalSecurityConfiguration";
            }
            
            @Override
            public void configureFromGlobalSecurity(StaplerRequest req, JSONObject js)
                    throws hudson.model.Descriptor.FormException
            {
                throw new FormException("Should not be called for global-security.jelly is not defined.", "");
            }
        }
    }
    
    /**
     * Test configuration in "Configure Global Security" is available.
     */
    public static class AuthorizeProjectStrategyWithGlobalSecurityConfiguration extends AuthorizeProjectStrategy {
        @Override
        public Authentication authenticate(AbstractProject<?, ?> project, Queue.Item item) {
            return null;
        }
        
        @TestExtension("testGlobalSecurityConfiguration")
        public static class DescriptorImpl extends AuthorizeProjectStrategyDescriptor {
            private String value;
            
            public String getValue() {
                return value;
            }
            
            public DescriptorImpl() {
                load();
            }
            
            @Override
            public String getDisplayName() {
                return "AuthorizeProjectStrategyWithGlobalSecurityConfiguration";
            }
            
            @Override
            public void configureFromGlobalSecurity(StaplerRequest req, JSONObject js)
                    throws hudson.model.Descriptor.FormException
            {
                value = js.getString("value");
                save();
            }
        }
    }
    
    /**
     * Test alternate file except global-security.jelly can be used.
     */
    public static class AuthorizeProjectStrategyWithAlternateGlobalSecurityConfiguration extends AuthorizeProjectStrategy {
        @Override
        public Authentication authenticate(AbstractProject<?, ?> project, Queue.Item item) {
            return null;
        }
        
        @TestExtension("testGlobalSecurityConfiguration")
        public static class DescriptorImpl extends AuthorizeProjectStrategyDescriptor {
            private String value;
            
            public String getValue() {
                return value;
            }
            
            public DescriptorImpl() {
                load();
            }
            
            @Override
            public String getDisplayName() {
                return "AuthorizeProjectStrategyWithAlternateGlobalSecurityConfiguration";
            }
            
            @Override
            public void configureFromGlobalSecurity(StaplerRequest req, JSONObject js)
                    throws hudson.model.Descriptor.FormException
            {
                value = js.getString("value");
                save();
            }
            
            @Override
            public String getGlobalSecurityConfigPage() {
                return getViewPage(clazz, "alternate.jelly");
            }
        }
    }
    
    @Test
    public void testGlobalSecurityConfiguration() throws Exception {
        AuthorizeProjectStrategyWithGlobalSecurityConfiguration.DescriptorImpl descriptor
            = (AuthorizeProjectStrategyWithGlobalSecurityConfiguration.DescriptorImpl)Jenkins.getInstance().getDescriptor(AuthorizeProjectStrategyWithGlobalSecurityConfiguration.class);
        AuthorizeProjectStrategyWithAlternateGlobalSecurityConfiguration.DescriptorImpl alternateDescriptor
            = (AuthorizeProjectStrategyWithAlternateGlobalSecurityConfiguration.DescriptorImpl)Jenkins.getInstance().getDescriptor(AuthorizeProjectStrategyWithAlternateGlobalSecurityConfiguration.class);
        
        final String value1 = "value1 for AuthorizeProjectStrategyWithGlobalSecurityConfigurationValueField";
        final String alternateValue1 = "value1 for AuthorizeProjectStrategyWithAlternateGlobalSecurityConfiguration";
        
        WebClient wc = j.createWebClient();
        
        // access to Configure Global Security.
        {
            assertNull(descriptor.getValue());
            assertNull(alternateDescriptor.getValue());
            
            HtmlPage page = wc.goTo("configureSecurity");
            System.out.println(page.asXml());
            HtmlForm form = page.getFormByName("config");
            
            // verify global-security.jelly is displayed
            HtmlTextInput valueField = form.getElementById("AuthorizeProjectStrategyWithGlobalSecurityConfigurationValueField");
            assertNotNull(valueField);
            assertEquals("", valueField.getValueAttribute());
            
            // verify alternate.jelly is displayed
            HtmlTextInput alternateField = form.getElementById("AuthorizeProjectStrategyWithAlternateGlobalSecurityConfiguration");
            assertNotNull(alternateField);
            assertEquals("", alternateField.getValueAttribute());
            
            valueField.setValueAttribute(value1);
            alternateField.setValueAttribute(alternateValue1);
            
            j.submit(form);
            
            assertEquals(value1, descriptor.getValue());
            assertEquals(alternateValue1, alternateDescriptor.getValue());
        }
        
        // field is displayed again
        {
            HtmlPage page = wc.goTo("configureSecurity");
            HtmlForm form = page.getFormByName("config");
            
            // verify global-security.jelly is displayed
            HtmlTextInput valueField = form.getElementById("AuthorizeProjectStrategyWithGlobalSecurityConfigurationValueField");
            assertNotNull(valueField);
            assertEquals(value1, valueField.getValueAttribute());
            
            // verify alternate.jelly is displayed
            HtmlTextInput alternateField = form.getElementById("AuthorizeProjectStrategyWithAlternateGlobalSecurityConfiguration");
            assertNotNull(alternateField);
            assertEquals(alternateValue1, alternateField.getValueAttribute());
        }
        
    }
}
