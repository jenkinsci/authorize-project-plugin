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
import hudson.model.FreeStyleBuild;
import hudson.model.FreeStyleProject;
import hudson.security.ACL;
import hudson.tasks.BuildTrigger;

import org.jenkinsci.plugins.authorizeproject.AuthorizeProjectProperty;
import org.jenkinsci.plugins.authorizeproject.testutil.AuthorizationCheckBuilder;
import org.jenkinsci.plugins.authorizeproject.testutil.AuthorizeProjectJenkinsRule;
import org.junit.Rule;
import org.junit.Test;
import org.jvnet.hudson.test.JenkinsRule;
import org.jvnet.hudson.test.JenkinsRule.WebClient;
import org.jvnet.hudson.test.recipes.LocalData;

/**
 *
 */
public class TriggeringUsersAuthorizationStrategyTest {
    @Rule
    public JenkinsRule j = new AuthorizeProjectJenkinsRule();
    
    private void triggerBuildWithoutParameters(WebClient wc, FreeStyleProject project) throws Exception {
        // This code may get not to work in future versions of Jenkins.
        // There are several problems:
        // * A form to resend a request with POST method has no name attribute.
        // * A button to submit is differ from that of other forms in Jenkins.
        //   (other forms is with <BUTTON>, but this form is with <SUBMIT>.
        wc.getPage(project, "build").getFormByName("").submit();
    }
    
    @Test
    @LocalData
    public void testAuthenticate() throws Exception {
        FreeStyleProject p = j.createFreeStyleProject();
        AuthorizationCheckBuilder checker = new AuthorizationCheckBuilder();
        p.getBuildersList().add(checker);
        
        // if not configured, run in SYSTEM privilege.
        {
            assertNull(p.getLastBuild());
            WebClient wc = j.createWebClient();
            triggerBuildWithoutParameters(wc, p);
            j.waitUntilNoActivity();
            FreeStyleBuild b = p.getLastBuild();
            assertNotNull(b);
            j.assertBuildStatusSuccess(b);
            
            assertEquals(ACL.SYSTEM, checker.authentication);
            b.delete();
        }
        
        p.addProperty(new AuthorizeProjectProperty(new TriggeringUsersAuthorizationStrategy()));
        
        // if configured, run in ANONYMOUS privilege.
        {
            assertNull(p.getLastBuild());
            WebClient wc = j.createWebClient();
            triggerBuildWithoutParameters(wc, p);
            j.waitUntilNoActivity();
            FreeStyleBuild b = p.getLastBuild();
            assertNotNull(b);
            j.assertBuildStatusSuccess(b);
            
            assertEquals(Jenkins.ANONYMOUS, checker.authentication);
            b.delete();
        }
        
        // if triggered from a user, run in the privilege of that user.
        {
            assertNull(p.getLastBuild());
            WebClient wc = j.createWebClient().login("test1", "test1");
            triggerBuildWithoutParameters(wc, p);
            j.waitUntilNoActivity();
            FreeStyleBuild b = p.getLastBuild();
            assertNotNull(b);
            j.assertBuildStatusSuccess(b);
            
            assertEquals("test1", checker.authentication.getName());
            b.delete();
        }
        
        // test with another user.
        {
            assertNull(p.getLastBuild());
            WebClient wc = j.createWebClient().login("test2", "test2");
            triggerBuildWithoutParameters(wc, p);
            j.waitUntilNoActivity();
            FreeStyleBuild b = p.getLastBuild();
            assertNotNull(b);
            j.assertBuildStatusSuccess(b);
            
            assertEquals("test2", checker.authentication.getName());
            b.delete();
        }
    }
    
    @Test
    @LocalData
    public void testAuthenticateDownstream() throws Exception {
        FreeStyleProject p = j.createFreeStyleProject();
        AuthorizationCheckBuilder checker = new AuthorizationCheckBuilder();
        p.getBuildersList().add(checker);
        p.addProperty(new AuthorizeProjectProperty(new TriggeringUsersAuthorizationStrategy()));
        
        FreeStyleProject upstream = j.createFreeStyleProject();
        upstream.getPublishersList().add(new BuildTrigger(p.getFullName(), false));
        
        j.jenkins.rebuildDependencyGraph();
        
        // if triggered from a user, its downstream runs in the privilege of that user.
        {
            assertNull(p.getLastBuild());
            WebClient wc = j.createWebClient().login("test1", "test1");
            triggerBuildWithoutParameters(wc, upstream);
            j.waitUntilNoActivity();
            FreeStyleBuild b = p.getLastBuild();
            assertNotNull(b);
            j.assertBuildStatusSuccess(b);
            
            assertEquals("test1", checker.authentication.getName());
            b.delete();
        }
    }
}
