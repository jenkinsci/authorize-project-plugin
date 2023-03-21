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

import java.util.Collections;
import java.util.HashSet;
import java.util.Set;

import jenkins.model.Jenkins;
import jenkins.security.QueueItemAuthenticatorConfiguration;
import hudson.matrix.AxisList;
import hudson.matrix.MatrixProject;
import hudson.matrix.TextAxis;
import hudson.model.AbstractProject;
import hudson.model.Descriptor;
import hudson.model.FreeStyleProject;
import hudson.model.InvisibleAction;
import hudson.model.Job;
import hudson.model.Queue;
import hudson.model.Run;
import hudson.model.TaskListener;
import hudson.model.User;
import hudson.security.ACL;
import hudson.tasks.BuildStepDescriptor;
import hudson.tasks.Builder;
import jenkins.tasks.SimpleBuildStep;
import net.sf.json.JSONObject;

import org.acegisecurity.Authentication;
import org.jenkinsci.plugins.authorizeproject.strategy.AnonymousAuthorizationStrategy;
import org.jenkinsci.plugins.authorizeproject.strategy.SpecificUsersAuthorizationStrategy;
import org.jenkinsci.plugins.authorizeproject.testutil.AuthorizationCheckBuilder;
import org.jenkinsci.plugins.authorizeproject.testutil.AuthorizeProjectJenkinsRule;
import org.jenkinsci.plugins.workflow.cps.CpsFlowDefinition;
import org.jenkinsci.plugins.workflow.job.WorkflowJob;
import org.jenkinsci.plugins.workflow.job.WorkflowRun;
import org.junit.Rule;
import org.junit.Test;
import org.jvnet.hudson.test.JenkinsRule;
import org.jvnet.hudson.test.JenkinsRule.WebClient;
import org.jvnet.hudson.test.TestExtension;
import org.kohsuke.stapler.DataBoundConstructor;
import org.kohsuke.stapler.StaplerRequest;

import com.gargoylesoftware.htmlunit.html.HtmlForm;
import com.gargoylesoftware.htmlunit.html.HtmlPage;
import com.gargoylesoftware.htmlunit.html.HtmlTextInput;

import java.io.IOException;
import hudson.FilePath;
import hudson.Launcher;

/**
 *
 */
public class ProjectQueueItemAuthenticatorTest {
    @Rule
    public JenkinsRule j = new AuthorizeProjectJenkinsRule(SpecificUsersAuthorizationStrategy.class);
    
    public static class NullAuthorizeProjectStrategy extends AuthorizeProjectStrategy {
        @DataBoundConstructor
        public NullAuthorizeProjectStrategy() {
        }
        
        @Override
        public Authentication authenticate(Job<?, ?> project, Queue.Item item) {
            return null;
        }
        
        @TestExtension
        public static class DescriptorImpl extends AuthorizeProjectStrategyDescriptor {
            @Override
            public String getDisplayName() {
                return "NullAuthorizeProjectStrategy";
            }
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
            MatrixProject p = j.createProject(MatrixProject.class);
            p.setAxes(new AxisList(new TextAxis("axis1", "value1")));
            AuthorizationCheckBuilder checker = new AuthorizationCheckBuilder();
            p.getBuildersList().add(checker);
            
            j.assertBuildStatusSuccess(p.scheduleBuild2(0));
            assertEquals(ACL.SYSTEM, checker.authentication);
        }
        
        // if configured, AuthorizeProjectStrategy takes effect
        {
            MatrixProject p = j.createProject(MatrixProject.class);
            p.setAxes(new AxisList(new TextAxis("axis1", "value1")));
            AuthorizationCheckBuilder checker = new AuthorizationCheckBuilder();
            p.getBuildersList().add(checker);
            
            p.addProperty(new AuthorizeProjectProperty(new AnonymousAuthorizationStrategy()));
            
            j.assertBuildStatusSuccess(p.scheduleBuild2(0));
            assertEquals(Jenkins.ANONYMOUS, checker.authentication);
        }
        
        // if configured wrong, run in SYSTEM privilege.
        {
            MatrixProject p = j.createProject(MatrixProject.class);
            p.setAxes(new AxisList(new TextAxis("axis1", "value1")));
            AuthorizationCheckBuilder checker = new AuthorizationCheckBuilder();
            p.getBuildersList().add(checker);
            
            p.addProperty(new AuthorizeProjectProperty(null));
            
            j.assertBuildStatusSuccess(p.scheduleBuild2(0));
            assertEquals(ACL.SYSTEM, checker.authentication);
        }
        
        // if the strategy returns null, run in SYSTEM privilege.
        {
            MatrixProject p = j.createProject(MatrixProject.class);
            p.setAxes(new AxisList(new TextAxis("axis1", "value1")));
            AuthorizationCheckBuilder checker = new AuthorizationCheckBuilder();
            p.getBuildersList().add(checker);
            
            p.addProperty(new AuthorizeProjectProperty(new NullAuthorizeProjectStrategy()));
            
            j.assertBuildStatusSuccess(p.scheduleBuild2(0));
            assertEquals(ACL.SYSTEM, checker.authentication);
        }
    }
    
    @Test
    public void testDisabledInProjectAuthorization() throws Exception {
        FreeStyleProject p = j.createFreeStyleProject();
        p.addProperty(new AuthorizeProjectProperty(new AnonymousAuthorizationStrategy()));

        assertTrue(ProjectQueueItemAuthenticator.getConfigured().isStrategyEnabled(j.jenkins.getDescriptor(AnonymousAuthorizationStrategy.class)));

        j.submit(j.createWebClient().getPage(p, "authorization").getFormByName("config"));

        // can be reconfigured if it is enabled.
        assertEquals(AnonymousAuthorizationStrategy.class, p.getProperty(AuthorizeProjectProperty.class).getStrategy().getClass());

        Set<String> enabledStrategies = Collections.emptySet();
        Set<String> disabledStrategies = Collections.singleton(j.jenkins.getDescriptor(AnonymousAuthorizationStrategy.class).getId());

        QueueItemAuthenticatorConfiguration.get().getAuthenticators().clear();
        QueueItemAuthenticatorConfiguration.get().getAuthenticators().add(new ProjectQueueItemAuthenticator(enabledStrategies, disabledStrategies));

        assertFalse(ProjectQueueItemAuthenticator.getConfigured().isStrategyEnabled(j.jenkins.getDescriptor(AnonymousAuthorizationStrategy.class)));

        j.submit(j.createWebClient().getPage(p, "authorization").getFormByName("config"));

        // cannot be reconfigured if it is disabled.
        assertNotEquals(AnonymousAuthorizationStrategy.class, p.getProperty(AuthorizeProjectProperty.class).getStrategy().getClass());
    }

    @Test
    public void testDisabledAtRuntime() throws Exception {
        FreeStyleProject p = j.createFreeStyleProject();
        AuthorizationCheckBuilder checker = new AuthorizationCheckBuilder();
        p.getBuildersList().add(checker);
        p.addProperty(new AuthorizeProjectProperty(new AnonymousAuthorizationStrategy()));
        
        assertTrue(ProjectQueueItemAuthenticator.getConfigured().isStrategyEnabled(j.jenkins.getDescriptor(AnonymousAuthorizationStrategy.class)));
        
        // strategy works if it is enabled
        j.assertBuildStatusSuccess(p.scheduleBuild2(0));
        assertEquals(Jenkins.ANONYMOUS, checker.authentication);
        
        Set<String> enabledStrategies = Collections.emptySet();
        Set<String> disabledStrategies = Collections.singleton(j.jenkins.getDescriptor(AnonymousAuthorizationStrategy.class).getId());
        
        QueueItemAuthenticatorConfiguration.get().getAuthenticators().clear();
        QueueItemAuthenticatorConfiguration.get().getAuthenticators().add(new ProjectQueueItemAuthenticator(enabledStrategies, disabledStrategies));
        
        assertFalse(ProjectQueueItemAuthenticator.getConfigured().isStrategyEnabled(j.jenkins.getDescriptor(AnonymousAuthorizationStrategy.class)));
        
        // strategy doesn't work if it is disabled even when it is configured
        j.assertBuildStatusSuccess(p.scheduleBuild2(0));
        assertEquals(ACL.SYSTEM, checker.authentication);
    }
    
    /**
     * Test no exception even if no global-security.jelly is not provided.
     */
    public static class AuthorizeProjectStrategyWithoutGlobalSecurityConfiguration extends AuthorizeProjectStrategy {
        @DataBoundConstructor
        public AuthorizeProjectStrategyWithoutGlobalSecurityConfiguration() {
        }

        @Override
        public Authentication authenticate(Job<?, ?> project, Queue.Item item) {
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
                    throws Descriptor.FormException
            {
                throw new FormException("Should not be called for global-security.jelly is not defined.", "");
            }
        }
    }
    
    /**
     * Test configuration in "Configure Global Security" is available.
     */
    public static class AuthorizeProjectStrategyWithGlobalSecurityConfiguration extends AuthorizeProjectStrategy {
        @DataBoundConstructor
        public AuthorizeProjectStrategyWithGlobalSecurityConfiguration() {
        }

        @Override
        public Authentication authenticate(Job<?, ?> project, Queue.Item item) {
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
                    throws Descriptor.FormException
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
        @DataBoundConstructor
        public AuthorizeProjectStrategyWithAlternateGlobalSecurityConfiguration() {
        }

        @Override
        public Authentication authenticate(Job<?, ?> project, Queue.Item item) {
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
                    throws Descriptor.FormException
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
            = (AuthorizeProjectStrategyWithGlobalSecurityConfiguration.DescriptorImpl)Jenkins.get().getDescriptor(AuthorizeProjectStrategyWithGlobalSecurityConfiguration.class);
        AuthorizeProjectStrategyWithAlternateGlobalSecurityConfiguration.DescriptorImpl alternateDescriptor
            = (AuthorizeProjectStrategyWithAlternateGlobalSecurityConfiguration.DescriptorImpl)Jenkins.get().getDescriptor(AuthorizeProjectStrategyWithAlternateGlobalSecurityConfiguration.class);
        
        final String value1 = "value1 for AuthorizeProjectStrategyWithGlobalSecurityConfigurationValueField";
        final String alternateValue1 = "value1 for AuthorizeProjectStrategyWithAlternateGlobalSecurityConfiguration";
        
        WebClient wc = j.createWebClient();
        
        // access to Configure Global Security.
        {
            assertNull(descriptor.getValue());
            assertNull(alternateDescriptor.getValue());
            
            HtmlPage page = wc.goTo("configureSecurity");
            HtmlForm form = page.getFormByName("config");
            
            // verify global-security.jelly is displayed
            HtmlTextInput valueField = form.getFirstByXPath("//input[@id='AuthorizeProjectStrategyWithGlobalSecurityConfigurationValueField']");
            assertNotNull(valueField);
            assertEquals("", valueField.getValueAttribute());
            
            // verify alternate.jelly is displayed
            HtmlTextInput alternateField = form.getFirstByXPath("//input[@id='AuthorizeProjectStrategyWithAlternateGlobalSecurityConfiguration']");
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
            HtmlTextInput valueField = form.getFirstByXPath("//input[@id='AuthorizeProjectStrategyWithGlobalSecurityConfigurationValueField']");
            assertNotNull(valueField);
            assertEquals(value1, valueField.getValueAttribute());
            
            // verify alternate.jelly is displayed
            HtmlTextInput alternateField = form.getFirstByXPath("//input[@id='AuthorizeProjectStrategyWithAlternateGlobalSecurityConfiguration']");
            assertNotNull(alternateField);
            assertEquals(alternateValue1, alternateField.getValueAttribute());
        }
        
        // enabled / disabled preservation
        Set<String> enabledStrategies;
        Set<String> disabledStrategies;

        // all are enabled
        enabledStrategies = new HashSet<>();
        disabledStrategies = new HashSet<>();
        enabledStrategies.add(j.jenkins.getDescriptor(AuthorizeProjectStrategyWithoutGlobalSecurityConfiguration.class).getId());
        enabledStrategies.add(j.jenkins.getDescriptor(AuthorizeProjectStrategyWithGlobalSecurityConfiguration.class).getId());
        enabledStrategies.add(j.jenkins.getDescriptor(AuthorizeProjectStrategyWithAlternateGlobalSecurityConfiguration.class).getId());
        assertStrategyEnablingConfigurationPreserved(enabledStrategies, disabledStrategies);
        
        // all are disabled
        enabledStrategies = new HashSet<>();
        disabledStrategies = new HashSet<>();
        disabledStrategies.add(j.jenkins.getDescriptor(AuthorizeProjectStrategyWithoutGlobalSecurityConfiguration.class).getId());
        disabledStrategies.add(j.jenkins.getDescriptor(AuthorizeProjectStrategyWithGlobalSecurityConfiguration.class).getId());
        disabledStrategies.add(j.jenkins.getDescriptor(AuthorizeProjectStrategyWithAlternateGlobalSecurityConfiguration.class).getId());
        assertStrategyEnablingConfigurationPreserved(enabledStrategies, disabledStrategies);
        
        // mixed
        enabledStrategies = new HashSet<>();
        disabledStrategies = new HashSet<>();
        disabledStrategies.add(j.jenkins.getDescriptor(AuthorizeProjectStrategyWithoutGlobalSecurityConfiguration.class).getId());
        enabledStrategies.add(j.jenkins.getDescriptor(AuthorizeProjectStrategyWithGlobalSecurityConfiguration.class).getId());
        disabledStrategies.add(j.jenkins.getDescriptor(AuthorizeProjectStrategyWithAlternateGlobalSecurityConfiguration.class).getId());
        assertStrategyEnablingConfigurationPreserved(enabledStrategies, disabledStrategies);
    }
    
    public void assertStrategyEnablingConfigurationPreserved(Set<String> enabledStrategies, Set<String> disabledStrategies) throws Exception {
        QueueItemAuthenticatorConfiguration.get().getAuthenticators().clear();
        QueueItemAuthenticatorConfiguration.get().getAuthenticators().add(new ProjectQueueItemAuthenticator(enabledStrategies, disabledStrategies));
        j.submit(j.createWebClient().goTo("configureSecurity").getFormByName("config"));
        for (String enabledStrategy : enabledStrategies) {
            assertTrue(
                    enabledStrategy,
                    ProjectQueueItemAuthenticator.getConfigured().isStrategyEnabled(
                            j.jenkins.getDescriptor(enabledStrategy)
                    )
            );
        }
        for (String disabledStrategy : disabledStrategies) {
            assertFalse(
                    disabledStrategy,
                    ProjectQueueItemAuthenticator.getConfigured().isStrategyEnabled(
                            j.jenkins.getDescriptor(disabledStrategy)
                    )
            );
        }
    }
    
    /**
     * Test alternate file except global-security.jelly can be used.
     */
    public static class AuthorizeProjectStrategyWithOldSignature extends AuthorizeProjectStrategy {
        private String name;

        @DataBoundConstructor
        public AuthorizeProjectStrategyWithOldSignature(String name) {
            this.name = name;
        }
        
        @Override
        public Authentication authenticate(AbstractProject<?, ?> project, Queue.Item item) {
            return User.getById(name, true).impersonate();
        }
        
        @TestExtension
        public static class DescriptorImpl extends AuthorizeProjectStrategyDescriptor {
            @Override
            public String getDisplayName() {
                return "AuthorizeProjectStrategyWithOldSignature";
            }
            
        }
    }
    
    @Test
    public void testOldSignature() throws Exception {
        j.jenkins.setSecurityRealm(j.createDummySecurityRealm());
        FreeStyleProject p = j.createFreeStyleProject();
        p.addProperty(new AuthorizeProjectProperty(new AuthorizeProjectStrategyWithOldSignature("test1")));
        AuthorizationCheckBuilder checker = new AuthorizationCheckBuilder();
        p.getBuildersList().add(checker);
        
        j.assertBuildStatusSuccess(p.scheduleBuild2(0));
        assertEquals("test1", checker.authentication.getName());
    }
    
    public static class AuthorizationRecordAction extends InvisibleAction {
        // transient because the UsernamePasswordAuthenticationToken is forbidden to be serialized by JEP-200
        public final transient Authentication authentication;
        
        public AuthorizationRecordAction(Authentication authentication) {
            this.authentication = authentication;
        }
    }
    
    public static class AuthorizationCheckSimpleBuilder extends Builder implements SimpleBuildStep {
        @DataBoundConstructor
        public AuthorizationCheckSimpleBuilder() {
        }
        
        @Override
        public void perform(Run<?, ?> run, FilePath workspace, Launcher launcher, TaskListener listener)
                throws InterruptedException, IOException {
            run.addAction(new AuthorizationRecordAction(Jenkins.getAuthentication()));
        }
        
        @TestExtension("testWorkflow")
        public static class DescriptorImpl extends BuildStepDescriptor<Builder> {
            @Override
            public boolean isApplicable(Class<? extends AbstractProject> jobType) {
                return true;
            }
            
            @Override
            public String getDisplayName() {
                return "AuthorizationCheckSimpleBuilder";
            }
        }
    }
    
    @Test
    public void testWorkflow() throws Exception {
        j.jenkins.setSecurityRealm(j.createDummySecurityRealm());
        {
            WorkflowJob p = j.jenkins.createProject(WorkflowJob.class, "test"+j.jenkins.getItems().size());
            p.setDefinition(new CpsFlowDefinition("node{ step([$class: 'AuthorizationCheckSimpleBuilder']); }", true));
            WorkflowRun b = p.scheduleBuild2(0).get();
            j.assertBuildStatusSuccess(b);
            assertEquals(ACL.SYSTEM, b.getAction(AuthorizationRecordAction.class).authentication);
        }
        {
            WorkflowJob p = j.jenkins.createProject(WorkflowJob.class, "test"+j.jenkins.getItems().size());
            p.addProperty(new AuthorizeProjectProperty(new AuthorizeProjectStrategyWithOldSignature("test1")));
            p.setDefinition(new CpsFlowDefinition("node{ step([$class: 'AuthorizationCheckSimpleBuilder']); }", true));
            WorkflowRun b = p.scheduleBuild2(0).get();
            j.assertBuildStatusSuccess(b);
            // Strategies with old signatures don't work for Jobs.
            assertEquals(ACL.SYSTEM, b.getAction(AuthorizationRecordAction.class).authentication);
        }
        
        {
            WorkflowJob p = j.jenkins.createProject(WorkflowJob.class, "test"+j.jenkins.getItems().size());
            p.addProperty(new AuthorizeProjectProperty(new SpecificUsersAuthorizationStrategy("test1")));
            User.getById("test1", true);  // create
            p.setDefinition(new CpsFlowDefinition("node{ step([$class: 'AuthorizationCheckSimpleBuilder']); }", true));
            WorkflowRun b = p.scheduleBuild2(0).get();
            j.assertBuildStatusSuccess(b);
            assertEquals(User.getById("test1", false).impersonate(), b.getAction(AuthorizationRecordAction.class).authentication);
        }
    }
}
