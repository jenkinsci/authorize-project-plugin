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

import java.io.ByteArrayInputStream;
import java.io.StringWriter;
import java.net.URL;
import java.util.Arrays;
import java.util.HashMap;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.TimeUnit;

import javax.xml.transform.Transformer;
import javax.xml.transform.TransformerException;
import javax.xml.transform.TransformerFactory;
import javax.xml.transform.dom.DOMSource;
import javax.xml.transform.stream.StreamResult;

import jenkins.model.Jenkins;
import jenkins.security.ApiTokenProperty;
import hudson.cli.CLI;
import hudson.model.Item;
import hudson.model.FreeStyleProject;
import hudson.model.ParametersDefinitionProperty;
import hudson.model.StringParameterDefinition;
import hudson.model.User;
import hudson.security.ACL;
import hudson.security.AuthorizationMatrixProperty;
import hudson.security.GlobalMatrixAuthorizationStrategy;
import hudson.security.Permission;
import hudson.security.ProjectMatrixAuthorizationStrategy;

import org.apache.commons.io.input.NullInputStream;
import org.apache.commons.io.output.ByteArrayOutputStream;
import org.jenkinsci.plugins.authorizeproject.AuthorizeProjectProperty;
import org.jenkinsci.plugins.authorizeproject.testutil.AuthorizationCheckBuilder;
import org.jenkinsci.plugins.authorizeproject.testutil.AuthorizeProjectJenkinsRule;
import org.jenkinsci.plugins.authorizeproject.testutil.SecurityRealmWithUserFilter;
import org.junit.Rule;
import org.junit.Test;
import org.jvnet.hudson.test.JenkinsRule;
import org.jvnet.hudson.test.JenkinsRule.WebClient;
import org.jvnet.hudson.test.recipes.LocalData;
import org.w3c.dom.Document;

import com.gargoylesoftware.htmlunit.FailingHttpStatusCodeException;
import com.gargoylesoftware.htmlunit.HttpMethod;
import com.gargoylesoftware.htmlunit.WebRequest;
import com.gargoylesoftware.htmlunit.html.HtmlCheckBoxInput;
import com.gargoylesoftware.htmlunit.html.HtmlPage;
import com.gargoylesoftware.htmlunit.html.HtmlPasswordInput;
import com.gargoylesoftware.htmlunit.html.HtmlTextInput;
import com.gargoylesoftware.htmlunit.xml.XmlPage;
import com.google.common.collect.Sets;

/**
 *
 */
public class SpecificUsersAuthorizationStrategyTest {
    @Rule
    public JenkinsRule j = new AuthorizeProjectJenkinsRule(SpecificUsersAuthorizationStrategy.class);
    
    private void prepareSecurity() {
        // This allows any users authenticate name == password
        j.jenkins.setSecurityRealm(j.createDummySecurityRealm());
        
        GlobalMatrixAuthorizationStrategy authorization = new GlobalMatrixAuthorizationStrategy();
        authorization.add(Jenkins.ADMINISTER, "admin");
        authorization.add(Jenkins.READ, "test1");
        authorization.add(Item.READ, "test1");
        authorization.add(Item.CONFIGURE, "test1");
        authorization.add(Jenkins.READ, "test2");
        authorization.add(Item.READ, "test2");
        authorization.add(Item.CONFIGURE, "test2");
        
        // This is required for CLI, JENKINS-12543.
        authorization.add(Jenkins.READ, "anonymous");
        authorization.add(Item.READ, "anonymous");
        
        j.jenkins.setAuthorizationStrategy(authorization);
    }
    
    private void prepareJobBasedSecurity() {
        // This allows any users authenticate name == password
        j.jenkins.setSecurityRealm(j.createDummySecurityRealm());
        
        ProjectMatrixAuthorizationStrategy authorization = new ProjectMatrixAuthorizationStrategy();
        authorization.add(Jenkins.ADMINISTER, "admin");
        
        // This is required for CLI, JENKINS-12543.
        authorization.add(Jenkins.READ, "anonymous");
        authorization.add(Item.READ, "anonymous");
        
        j.jenkins.setAuthorizationStrategy(authorization);
    }
    
    @Test
    @LocalData
    public void testIsAuthenticateionRequiredAsUser() {
        ACL.impersonate(User.get("test1").impersonate());
        assertFalse(Jenkins.getInstance().hasPermission(Jenkins.ADMINISTER));
        assertFalse(SpecificUsersAuthorizationStrategy.isAuthenticationRequired("test1"));
        assertTrue(SpecificUsersAuthorizationStrategy.isAuthenticationRequired("test2"));
        assertTrue(SpecificUsersAuthorizationStrategy.isAuthenticationRequired("admin"));
    }
    
    @Test
    @LocalData
    public void testIsAuthenticateionRequiredAsAdministrator() {
        ACL.impersonate(User.get("admin").impersonate());
        assertTrue(Jenkins.getInstance().hasPermission(Jenkins.ADMINISTER));
        assertFalse(SpecificUsersAuthorizationStrategy.isAuthenticationRequired("test2"));
    }
    
    @Test
    @LocalData
    public void testIsAuthenticateionRequiredAnonymous() {
        ACL.impersonate(Jenkins.ANONYMOUS);
        assertFalse(Jenkins.getInstance().hasPermission(Jenkins.ADMINISTER));
        assertTrue(SpecificUsersAuthorizationStrategy.isAuthenticationRequired("test2"));
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
            FreeStyleProject p = j.createFreeStyleProject();
            p.addProperty(new ParametersDefinitionProperty(new StringParameterDefinition("foo", "bar")));
            p.addProperty(new AuthorizeProjectProperty(new SpecificUsersAuthorizationStrategy(userid)));
            SpecificUsersAuthorizationStrategy s = SpecificUsersAuthorizationStrategy.getCurrentStrategy(p);
            assertNotNull(p);
            assertEquals(userid, s.getUserid());
        }
    }
    
    @Test
    @LocalData
    public void testAuthenticateWithPassword() throws Exception {
        assertTrue(SpecificUsersAuthorizationStrategy.authenticate("test1", false, null, "test1"));
        assertFalse(SpecificUsersAuthorizationStrategy.authenticate("test1", false, null, "test2"));
        assertFalse(SpecificUsersAuthorizationStrategy.authenticate("test1", false, null, ""));
        assertFalse(SpecificUsersAuthorizationStrategy.authenticate("", false, null, "test2"));
        assertFalse(SpecificUsersAuthorizationStrategy.authenticate("test1", false, null, null));
        assertFalse(SpecificUsersAuthorizationStrategy.authenticate(null, false, null, "test2"));
    }
    
    @Test
    public void testAuthenticateWithApitoken() throws Exception {
        prepareSecurity();
        String apitokenForTest1 = User.get("test1").getProperty(ApiTokenProperty.class).getApiToken();
        
        assertTrue(SpecificUsersAuthorizationStrategy.authenticate("test1", true, apitokenForTest1, null));
        assertFalse(SpecificUsersAuthorizationStrategy.authenticate("test1", true, apitokenForTest1 + "xxx", null));
        assertFalse(SpecificUsersAuthorizationStrategy.authenticate("test1", true, "", null));
        assertFalse(SpecificUsersAuthorizationStrategy.authenticate("", true, apitokenForTest1, null));
        assertFalse(SpecificUsersAuthorizationStrategy.authenticate("test1", true, null, null));
        assertFalse(SpecificUsersAuthorizationStrategy.authenticate(null, true, apitokenForTest1, null));
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
            
            p.addProperty(new AuthorizeProjectProperty(new SpecificUsersAuthorizationStrategy("test1")));
            
            j.assertBuildStatusSuccess(p.scheduleBuild2(0));
            assertEquals("test1", checker.authentication.getName());
        }
        
        // if configured, run in specified user.
        {
            FreeStyleProject p = j.createFreeStyleProject();
            AuthorizationCheckBuilder checker = new AuthorizationCheckBuilder();
            p.getBuildersList().add(checker);
            
            p.addProperty(new AuthorizeProjectProperty(new SpecificUsersAuthorizationStrategy("admin")));
            
            j.assertBuildStatusSuccess(p.scheduleBuild2(0));
            assertEquals("admin", checker.authentication.getName());
        }
        
        // invalid user
        {
            FreeStyleProject p = j.createFreeStyleProject();
            AuthorizationCheckBuilder checker = new AuthorizationCheckBuilder();
            p.getBuildersList().add(checker);
            
            p.addProperty(new AuthorizeProjectProperty(new SpecificUsersAuthorizationStrategy("nosuchuser")));
            
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
            
            p.addProperty(new AuthorizeProjectProperty(new SpecificUsersAuthorizationStrategy(null)));
            
            j.assertBuildStatusSuccess(p.scheduleBuild2(0));
            assertEquals(Jenkins.ANONYMOUS, checker.authentication);
        }
    }
    
    @Test
    public void testUsernotFoundException() throws Exception {
        j.jenkins.setSecurityRealm(new SecurityRealmWithUserFilter(
                j.createDummySecurityRealm(),
                Arrays.asList("validuser")
        ));
        
        // Users should be created before the test.
        User.get("validuser");
        User.get("invaliduser");
        
        FreeStyleProject p = j.createFreeStyleProject();
        AuthorizationCheckBuilder checker = new AuthorizationCheckBuilder();
        p.getBuildersList().add(checker);
        
        p.removeProperty(AuthorizeProjectProperty.class);
        p.addProperty(new AuthorizeProjectProperty(new SpecificUsersAuthorizationStrategy("validuser")));
        
        j.assertBuildStatusSuccess(p.scheduleBuild2(0).get(10, TimeUnit.SECONDS));
        assertEquals("validuser", checker.authentication.getName());
        
        // In case of specifying an invalid user,
        // falls back to anonymous.
        // And the build should not be blocked.
        p.removeProperty(AuthorizeProjectProperty.class);
        p.addProperty(new AuthorizeProjectProperty(new SpecificUsersAuthorizationStrategy("invaliduser")));
        
        j.assertBuildStatusSuccess(p.scheduleBuild2(0).get(10, TimeUnit.SECONDS));
        assertEquals(Jenkins.ANONYMOUS, checker.authentication);
    }
    
    @Test
    @LocalData
    public void testLoadOnStart() throws Exception {
        // verify that SpecificUserAuthorizationStrategy is loaded correctly from the disk on startup.
        {
            FreeStyleProject p = j.jenkins.getItemByFullName("test", FreeStyleProject.class);
            assertNotNull(p);
            AuthorizeProjectProperty prop = p.getProperty(AuthorizeProjectProperty.class);
            assertNotNull(prop);
            assertEquals(SpecificUsersAuthorizationStrategy.class, prop.getStrategy().getClass());
            SpecificUsersAuthorizationStrategy strategy = (SpecificUsersAuthorizationStrategy)prop.getStrategy();
            assertEquals("test1", strategy.getUserid());
        }
        
        j.jenkins.reload();
        
        // verify that SpecificUserAuthorizationStrategy is reloaded correctly from the disk.
        {
            FreeStyleProject p = j.jenkins.getItemByFullName("test", FreeStyleProject.class);
            assertNotNull(p);
            AuthorizeProjectProperty prop = p.getProperty(AuthorizeProjectProperty.class);
            assertNotNull(prop);
            assertEquals(SpecificUsersAuthorizationStrategy.class, prop.getStrategy().getClass());
            SpecificUsersAuthorizationStrategy strategy = (SpecificUsersAuthorizationStrategy)prop.getStrategy();
            assertEquals("test1", strategy.getUserid());
        }
    }
    
    private String getConfigXml(XmlPage page) throws TransformerException {
        // {@link XmlPage#asXml} does unneccessary indentations.
        Document doc = page.getXmlDocument();
        TransformerFactory tfactory = TransformerFactory.newInstance(); 
        Transformer transformer = tfactory.newTransformer(); 
        
        StringWriter sw = new StringWriter();
        transformer.transform(new DOMSource(doc), new StreamResult(sw)); 
        
        return sw.toString();
    }
    
    @Test
    public void testRestInterfaceSuccess() throws Exception {
        prepareSecurity();
        
        FreeStyleProject srcProject = j.createFreeStyleProject();
        srcProject.addProperty(new AuthorizeProjectProperty(new SpecificUsersAuthorizationStrategy("test1")));
        srcProject.save();
        
        WebClient wc = j.createWebClient();
        wc.login("test1", "test1");
        
        // GET config.xml of srcProject (userid is set to test1)
        String configXml = getConfigXml(wc.goToXml(String.format("%s/config.xml", srcProject.getUrl())));
        
        // POST config.xml of srcProject (userid is set to test1) to a new project.
        // This should success.
        FreeStyleProject destProject = j.createFreeStyleProject();
        destProject.save();
        String projectName = destProject.getFullName();
        
        WebRequest req = new WebRequest(
                new URL(wc.getContextPath() + String.format("%s/config.xml", destProject.getUrl())),
                HttpMethod.POST
        );
        req.setAdditionalHeader(
                j.jenkins.getCrumbIssuer().getCrumbRequestField(),
                j.jenkins.getCrumbIssuer().getCrumb(null)
        );
        req.setRequestBody(configXml);
        wc.getPage(req);
        
        {
            FreeStyleProject p = j.jenkins.getItemByFullName(projectName, FreeStyleProject.class);
            assertNotNull(p);
            AuthorizeProjectProperty prop = p.getProperty(AuthorizeProjectProperty.class);
            assertNotNull(prop);
            assertEquals(SpecificUsersAuthorizationStrategy.class, prop.getStrategy().getClass());
            SpecificUsersAuthorizationStrategy strategy = (SpecificUsersAuthorizationStrategy)prop.getStrategy();
            assertEquals("test1", strategy.getUserid());
        }
        
        j.jenkins.reload();
        
        {
            FreeStyleProject p = j.jenkins.getItemByFullName(projectName, FreeStyleProject.class);
            assertNotNull(p);
            AuthorizeProjectProperty prop = p.getProperty(AuthorizeProjectProperty.class);
            assertNotNull(prop);
            assertEquals(SpecificUsersAuthorizationStrategy.class, prop.getStrategy().getClass());
            SpecificUsersAuthorizationStrategy strategy = (SpecificUsersAuthorizationStrategy)prop.getStrategy();
            assertEquals("test1", strategy.getUserid());
        }
    }
    
    @Test
    public void testRestInterfaceFailure() throws Exception {
        prepareSecurity();
        
        FreeStyleProject srcProject = j.createFreeStyleProject();
        srcProject.addProperty(new AuthorizeProjectProperty(new SpecificUsersAuthorizationStrategy("admin")));
        srcProject.save();
        
        WebClient wc = j.createWebClient();
        wc.login("test1", "test1");
        
        // GET config.xml of srcProject (userid is set to admin)
        String configXml = getConfigXml(wc.goToXml(String.format("%s/config.xml", srcProject.getUrl())));
        
        // POST config.xml of srcProject (userid is set to admin) to a new project.
        // This should fail.
        FreeStyleProject destProject = j.createFreeStyleProject();
        destProject.save();
        String projectName = destProject.getFullName();
        
        WebRequest req = new WebRequest(
                new URL(wc.getContextPath() + String.format("%s/config.xml", destProject.getUrl())),
                HttpMethod.POST
        );
        req.setAdditionalHeader(
                j.jenkins.getCrumbIssuer().getCrumbRequestField(),
                j.jenkins.getCrumbIssuer().getCrumb(null)
        );
        req.setRequestBody(configXml);
        
        try {
            wc.getPage(req);
            fail();
        } catch(FailingHttpStatusCodeException e) {
        }
        
        {
            FreeStyleProject p = j.jenkins.getItemByFullName(projectName, FreeStyleProject.class);
            assertNotNull(p);
            AuthorizeProjectProperty prop = p.getProperty(AuthorizeProjectProperty.class);
            assertTrue(
                    prop == null
                    || prop.getStrategy() == null
            );
        }
        
        j.jenkins.reload();
        
        {
            FreeStyleProject p = j.jenkins.getItemByFullName(projectName, FreeStyleProject.class);
            assertNotNull(p);
            AuthorizeProjectProperty prop = p.getProperty(AuthorizeProjectProperty.class);
            assertTrue(
                    prop == null
                    || prop.getStrategy() == null
            );
        }
    }
    
    @Test
    public void testCliSuccess() throws Exception {
        prepareSecurity();
        
        FreeStyleProject srcProject = j.createFreeStyleProject();
        srcProject.addProperty(new AuthorizeProjectProperty(new SpecificUsersAuthorizationStrategy("test1")));
        srcProject.save();
        
        WebClient wc = j.createWebClient();
        wc.login("test1", "test1");
        
        // GET config.xml of srcProject (userid is set to test1)
        String configXml = null;
        {
            CLI cli = new CLI(j.getURL());
            ByteArrayOutputStream stdout = new ByteArrayOutputStream();
            ByteArrayOutputStream stderr = new ByteArrayOutputStream();
            int ret = cli.execute(Arrays.asList(
                    "get-job",
                    srcProject.getFullName(),
                    "--username",
                    "test1",
                    "--password",
                    "test1"
                ),
                new NullInputStream(0),
                stdout,
                stderr
            );
            assertEquals(stderr.toString(), 0, ret);
            configXml = stdout.toString();
        }
        
        // POST config.xml of srcProject (userid is set to test1) to a new project.
        // This should success.
        FreeStyleProject destProject = j.createFreeStyleProject();
        destProject.save();
        String projectName = destProject.getFullName();
        
        {
            CLI cli = new CLI(j.getURL());
            ByteArrayOutputStream stdout = new ByteArrayOutputStream();
            ByteArrayOutputStream stderr = new ByteArrayOutputStream();
            int ret = cli.execute(Arrays.asList(
                    "update-job",
                    destProject.getFullName(),
                    "--username",
                    "test1",
                    "--password",
                    "test1"
                ),
                new ByteArrayInputStream(configXml.getBytes()),
                stdout,
                stderr
            );
            assertEquals(stderr.toString(), 0, ret);
        }
        
        {
            FreeStyleProject p = j.jenkins.getItemByFullName(projectName, FreeStyleProject.class);
            assertNotNull(p);
            AuthorizeProjectProperty prop = p.getProperty(AuthorizeProjectProperty.class);
            assertNotNull(prop);
            assertEquals(SpecificUsersAuthorizationStrategy.class, prop.getStrategy().getClass());
            SpecificUsersAuthorizationStrategy strategy = (SpecificUsersAuthorizationStrategy)prop.getStrategy();
            assertEquals("test1", strategy.getUserid());
        }
        
        j.jenkins.reload();
        
        {
            FreeStyleProject p = j.jenkins.getItemByFullName(projectName, FreeStyleProject.class);
            assertNotNull(p);
            AuthorizeProjectProperty prop = p.getProperty(AuthorizeProjectProperty.class);
            assertNotNull(prop);
            assertEquals(SpecificUsersAuthorizationStrategy.class, prop.getStrategy().getClass());
            SpecificUsersAuthorizationStrategy strategy = (SpecificUsersAuthorizationStrategy)prop.getStrategy();
            assertEquals("test1", strategy.getUserid());
        }
    }
    
    
    @Test
    public void testCliFailure() throws Exception {
        prepareSecurity();
        
        FreeStyleProject srcProject = j.createFreeStyleProject();
        srcProject.addProperty(new AuthorizeProjectProperty(new SpecificUsersAuthorizationStrategy("admin")));
        srcProject.save();
        
        WebClient wc = j.createWebClient();
        wc.login("test1", "test1");
        
        // GET config.xml of srcProject (userid is set to admin)
        String configXml = null;
        {
            CLI cli = new CLI(j.getURL());
            ByteArrayOutputStream stdout = new ByteArrayOutputStream();
            ByteArrayOutputStream stderr = new ByteArrayOutputStream();
            int ret = cli.execute(Arrays.asList(
                    "get-job",
                    srcProject.getFullName(),
                    "--username",
                    "test1",
                    "--password",
                    "test1"
                ),
                new NullInputStream(0),
                stdout,
                stderr
            );
            assertEquals(stderr.toString(), 0, ret);
            configXml = stdout.toString();
        }
        
        // POST config.xml of srcProject (userid is set to admin) to a new project.
        // This should fail.
        FreeStyleProject destProject = j.createFreeStyleProject();
        destProject.save();
        String projectName = destProject.getFullName();
        
        {
            CLI cli = new CLI(j.getURL());
            ByteArrayOutputStream stdout = new ByteArrayOutputStream();
            ByteArrayOutputStream stderr = new ByteArrayOutputStream();
            int ret = cli.execute(Arrays.asList(
                    "update-job",
                    destProject.getFullName(),
                    "--username",
                    "test1",
                    "--password",
                    "test1"
                ),
                new ByteArrayInputStream(configXml.getBytes()),
                stdout,
                stderr
            );
            assertNotEquals(0, ret);
        }
        
        {
            FreeStyleProject p = j.jenkins.getItemByFullName(projectName, FreeStyleProject.class);
            assertNotNull(p);
            AuthorizeProjectProperty prop = p.getProperty(AuthorizeProjectProperty.class);
            assertTrue(
                    prop == null
                    || prop.getStrategy() == null
            );
        }
        
        j.jenkins.reload();
        
        {
            FreeStyleProject p = j.jenkins.getItemByFullName(projectName, FreeStyleProject.class);
            assertNotNull(p);
            AuthorizeProjectProperty prop = p.getProperty(AuthorizeProjectProperty.class);
            assertTrue(
                    prop == null
                    || prop.getStrategy() == null
            );
        }
    }
    
    @Test
    public void testCliSuccessBySystemAdmin() throws Exception {
        prepareSecurity();
        
        FreeStyleProject srcProject = j.createFreeStyleProject();
        srcProject.addProperty(new AuthorizeProjectProperty(new SpecificUsersAuthorizationStrategy("test1")));
        srcProject.save();
        
        // GET config.xml of srcProject (userid is set to test1)
        String configXml = null;
        {
            CLI cli = new CLI(j.getURL());
            ByteArrayOutputStream stdout = new ByteArrayOutputStream();
            ByteArrayOutputStream stderr = new ByteArrayOutputStream();
            int ret = cli.execute(Arrays.asList(
                    "get-job",
                    srcProject.getFullName(),
                    "--username",
                    "admin",
                    "--password",
                    "admin"
                ),
                new NullInputStream(0),
                stdout,
                stderr
            );
            assertEquals(stderr.toString(), 0, ret);
            configXml = stdout.toString();
        }
        
        // POST config.xml of srcProject (userid is set to test1) to a new project.
        // This should success when the user is administrator of the system.
        FreeStyleProject destProject = j.createFreeStyleProject();
        destProject.save();
        String projectName = destProject.getFullName();
        
        {
            CLI cli = new CLI(j.getURL());
            ByteArrayOutputStream stdout = new ByteArrayOutputStream();
            ByteArrayOutputStream stderr = new ByteArrayOutputStream();
            int ret = cli.execute(Arrays.asList(
                    "update-job",
                    destProject.getFullName(),
                    "--username",
                    "admin",
                    "--password",
                    "admin"
                ),
                new ByteArrayInputStream(configXml.getBytes()),
                stdout,
                stderr
            );
            assertEquals(stderr.toString(), 0, ret);
        }
        
        {
            FreeStyleProject p = j.jenkins.getItemByFullName(projectName, FreeStyleProject.class);
            assertNotNull(p);
            AuthorizeProjectProperty prop = p.getProperty(AuthorizeProjectProperty.class);
            assertNotNull(prop);
            assertEquals(SpecificUsersAuthorizationStrategy.class, prop.getStrategy().getClass());
            SpecificUsersAuthorizationStrategy strategy = (SpecificUsersAuthorizationStrategy)prop.getStrategy();
            assertEquals("test1", strategy.getUserid());
        }
        
        j.jenkins.reload();
        
        {
            FreeStyleProject p = j.jenkins.getItemByFullName(projectName, FreeStyleProject.class);
            assertNotNull(p);
            AuthorizeProjectProperty prop = p.getProperty(AuthorizeProjectProperty.class);
            assertNotNull(prop);
            assertEquals(SpecificUsersAuthorizationStrategy.class, prop.getStrategy().getClass());
            SpecificUsersAuthorizationStrategy strategy = (SpecificUsersAuthorizationStrategy)prop.getStrategy();
            assertEquals("test1", strategy.getUserid());
        }
    }
    
    @Test
    public void testCliFailureEvenByJobAdmin() throws Exception {
        prepareJobBasedSecurity();
        
        FreeStyleProject srcProject = j.createFreeStyleProject();
        srcProject.addProperty(new AuthorizeProjectProperty(new SpecificUsersAuthorizationStrategy("admin")));
        {
            Map<Permission, Set<String>> authMap = new HashMap<>();
            authMap.put(Item.EXTENDED_READ, Sets.newHashSet("test1"));
            srcProject.addProperty(new AuthorizationMatrixProperty(authMap));
        }
        srcProject.save();
        
        // GET config.xml of srcProject (userid is set to admin)
        String configXml = null;
        {
            CLI cli = new CLI(j.getURL());
            ByteArrayOutputStream stdout = new ByteArrayOutputStream();
            ByteArrayOutputStream stderr = new ByteArrayOutputStream();
            int ret = cli.execute(Arrays.asList(
                    "get-job",
                    srcProject.getFullName(),
                    "--username",
                    "test1",
                    "--password",
                    "test1"
                ),
                new NullInputStream(0),
                stdout,
                stderr
            );
            assertEquals(stderr.toString(), 0, ret);
            configXml = stdout.toString();
        }
        
        // POST config.xml of srcProject (userid is set to test1) to a new project.
        // This should fail even if test1 is a administrator of the new job.
        FreeStyleProject destProject = j.createFreeStyleProject();
        {
            Map<Permission, Set<String>> authMap = new HashMap<>();
            authMap.put(Jenkins.ADMINISTER, Sets.newHashSet("test1"));
            destProject.addProperty(new AuthorizationMatrixProperty(authMap));
        }
        destProject.save();
        String projectName = destProject.getFullName();
        
        {
            CLI cli = new CLI(j.getURL());
            ByteArrayOutputStream stdout = new ByteArrayOutputStream();
            ByteArrayOutputStream stderr = new ByteArrayOutputStream();
            int ret = cli.execute(Arrays.asList(
                    "update-job",
                    destProject.getFullName(),
                    "--username",
                    "test1",
                    "--password",
                    "test1"
                ),
                new ByteArrayInputStream(configXml.getBytes()),
                stdout,
                stderr
            );
            assertNotEquals(0, ret);
        }
        
        {
            FreeStyleProject p = j.jenkins.getItemByFullName(projectName, FreeStyleProject.class);
            assertNotNull(p);
            AuthorizeProjectProperty prop = p.getProperty(AuthorizeProjectProperty.class);
            assertTrue(
                    prop == null
                    || prop.getStrategy() == null
            );
        }
        
        j.jenkins.reload();
        
        {
            FreeStyleProject p = j.jenkins.getItemByFullName(projectName, FreeStyleProject.class);
            assertNotNull(p);
            AuthorizeProjectProperty prop = p.getProperty(AuthorizeProjectProperty.class);
            assertTrue(
                    prop == null
                    || prop.getStrategy() == null
            );
        }
    }
    
    @Test
    public void testConfigurationAuthentication() throws Exception {
        prepareSecurity();
        
        FreeStyleProject p = j.createFreeStyleProject();
        
        WebClient wc = j.createWebClient();
        wc.login("test1");
        
        // Authentication is required if not current user
        p.removeProperty(AuthorizeProjectProperty.class);
        p.addProperty(new AuthorizeProjectProperty(new SpecificUsersAuthorizationStrategy("admin")));
        try {
            j.submit(wc.getPage(p, "authorization").getFormByName("config"));
            fail();
        } catch (FailingHttpStatusCodeException e) {
            assertEquals(403, e.getStatusCode());
        }
        
        // No authentication is required if oneself.
        {
            HtmlPage page = wc.getPage(p, "authorization");
            HtmlTextInput userid = page.<HtmlTextInput>getFirstByXPath("//*[contains(@class, 'specific-user-authorization')]//input[contains(@name, 'userid') and @type='text']");
            userid.setValueAttribute("test1");
            j.submit(page.getFormByName("config"));
            
            assertEquals("test1", ((SpecificUsersAuthorizationStrategy)p.getProperty(AuthorizeProjectProperty.class).getStrategy()).getUserid());
        }
        
        // Authentication is required to change userid to one that is not current user
        p.addProperty(new AuthorizeProjectProperty(new SpecificUsersAuthorizationStrategy("admin")));
        {
            HtmlPage page = wc.getPage(p, "authorization");
            HtmlTextInput userid = page.<HtmlTextInput>getFirstByXPath("//*[contains(@class, 'specific-user-authorization')]//input[contains(@name, 'userid') and @type='text']");
            userid.setValueAttribute("test2");
            try {
                j.submit(page.getFormByName("config"));
                fail();
            } catch (FailingHttpStatusCodeException e) {
                assertEquals(403, e.getStatusCode());
            }
        }
    }
    
    @Test
    public void testConfigurePassword() throws Exception {
        prepareSecurity();
        
        FreeStyleProject p = j.createFreeStyleProject();
        p.addProperty(new AuthorizeProjectProperty(new SpecificUsersAuthorizationStrategy("test2")));
        
        WebClient wc = j.createWebClient();
        wc.login("test1");
        
        // authentication fails without password
        {
            HtmlPage page = wc.getPage(p, "authorization");
            HtmlCheckBoxInput useApitoken = page.<HtmlCheckBoxInput>getFirstByXPath("//*[contains(@class, 'specific-user-authorization')]//input[contains(@name, 'useApitoken') and @type='checkbox']");
            useApitoken.setChecked(false);
            try {
                j.submit(page.getFormByName("config"));
                fail();
            } catch (FailingHttpStatusCodeException e) {
                assertEquals(403, e.getStatusCode());
            }
        }
        
        // authentication succeeds with the good password
        {
            HtmlPage page = wc.getPage(p, "authorization");
            HtmlCheckBoxInput useApitoken = page.<HtmlCheckBoxInput>getFirstByXPath("//*[contains(@class, 'specific-user-authorization')]//input[contains(@name, 'useApitoken') and @type='checkbox']");
            useApitoken.setChecked(false);
            HtmlPasswordInput password = page.<HtmlPasswordInput>getFirstByXPath("//*[contains(@class, 'specific-user-authorization')]//input[contains(@name, 'password') and @type='password']");
            password.setValueAttribute("test2");
            j.submit(page.getFormByName("config"));
            
            assertEquals("test2", ((SpecificUsersAuthorizationStrategy)p.getProperty(AuthorizeProjectProperty.class).getStrategy()).getUserid());
        }
        
        // authentication fails with a bad password
        {
            HtmlPage page = wc.getPage(p, "authorization");
            HtmlCheckBoxInput useApitoken = page.<HtmlCheckBoxInput>getFirstByXPath("//*[contains(@class, 'specific-user-authorization')]//input[contains(@name, 'useApitoken') and @type='checkbox']");
            useApitoken.setChecked(false);
            HtmlPasswordInput password = page.<HtmlPasswordInput>getFirstByXPath("//*[contains(@class, 'specific-user-authorization')]//input[contains(@name, 'password') and @type='password']");
            password.setValueAttribute("badpassword");
            try {
                j.submit(page.getFormByName("config"));
                fail();
            } catch (FailingHttpStatusCodeException e) {
                assertEquals(403, e.getStatusCode());
            }
        }
        
        // authentication fails if the password is used for apitoken
        {
            HtmlPage page = wc.getPage(p, "authorization");
            HtmlCheckBoxInput useApitoken = page.<HtmlCheckBoxInput>getFirstByXPath("//*[contains(@class, 'specific-user-authorization')]//input[contains(@name, 'useApitoken') and @type='checkbox']");
            useApitoken.setChecked(true);
            HtmlPasswordInput password = page.<HtmlPasswordInput>getFirstByXPath("//*[contains(@class, 'specific-user-authorization')]//input[contains(@name, 'password') and @type='password']");
            password.setValueAttribute("test2");
            HtmlTextInput apitoken = page.<HtmlTextInput>getFirstByXPath("//*[contains(@class, 'specific-user-authorization')]//input[contains(@name, 'apitoken') and @type='text']");
            apitoken.setValueAttribute("test2");
            try {
                j.submit(page.getFormByName("config"));
                fail();
            } catch (FailingHttpStatusCodeException e) {
                assertEquals(403, e.getStatusCode());
            }
        }
    }
    
    @Test
    public void testConfigureApitoken() throws Exception {
        prepareSecurity();
        
        FreeStyleProject p = j.createFreeStyleProject();
        p.addProperty(new AuthorizeProjectProperty(new SpecificUsersAuthorizationStrategy("test2")));
        
        WebClient wc = j.createWebClient();
        wc.login("test1");
        
        String apitokenForTest2 = User.get("test2").getProperty(ApiTokenProperty.class).getApiToken();
        assertNotNull(apitokenForTest2);
        assertNotEquals("", apitokenForTest2);
        
        // authentication fails without apitoken
        {
            HtmlPage page = wc.getPage(p, "authorization");
            HtmlCheckBoxInput useApitoken = page.<HtmlCheckBoxInput>getFirstByXPath("//*[contains(@class, 'specific-user-authorization')]//input[contains(@name, 'useApitoken') and @type='checkbox']");
            useApitoken.setChecked(true);
            try {
                j.submit(page.getFormByName("config"));
                fail();
            } catch (FailingHttpStatusCodeException e) {
                assertEquals(403, e.getStatusCode());
            }
        }
        
        // authentication succeeds with the good apitoken
        {
            HtmlPage page = wc.getPage(p, "authorization");
            HtmlCheckBoxInput useApitoken = page.<HtmlCheckBoxInput>getFirstByXPath("//*[contains(@class, 'specific-user-authorization')]//input[contains(@name, 'useApitoken') and @type='checkbox']");
            useApitoken.setChecked(true);
            HtmlTextInput apitoken = page.<HtmlTextInput>getFirstByXPath("//*[contains(@class, 'specific-user-authorization')]//input[contains(@name, 'apitoken') and @type='text']");
            apitoken.setValueAttribute(apitokenForTest2);
            j.submit(page.getFormByName("config"));
            
            assertEquals("test2", ((SpecificUsersAuthorizationStrategy)p.getProperty(AuthorizeProjectProperty.class).getStrategy()).getUserid());
        }
        
        // authentication fails with a bad apitoken
        {
            HtmlPage page = wc.getPage(p, "authorization");
            HtmlCheckBoxInput useApitoken = page.<HtmlCheckBoxInput>getFirstByXPath("//*[contains(@class, 'specific-user-authorization')]//input[contains(@name, 'useApitoken') and @type='checkbox']");
            useApitoken.setChecked(true);
            HtmlTextInput apitoken = page.<HtmlTextInput>getFirstByXPath("//*[contains(@class, 'specific-user-authorization')]//input[contains(@name, 'apitoken') and @type='text']");
            apitoken.setValueAttribute(apitokenForTest2 + "xxx");
            try {
                j.submit(page.getFormByName("config"));
                fail();
            } catch (FailingHttpStatusCodeException e) {
                assertEquals(403, e.getStatusCode());
            }
        }
        
        // authentication fails if the apitoken is used for password
        {
            HtmlPage page = wc.getPage(p, "authorization");
            HtmlCheckBoxInput useApitoken = page.<HtmlCheckBoxInput>getFirstByXPath("//*[contains(@class, 'specific-user-authorization')]//input[contains(@name, 'useApitoken') and @type='checkbox']");
            useApitoken.setChecked(false);
            HtmlPasswordInput password = page.<HtmlPasswordInput>getFirstByXPath("//*[contains(@class, 'specific-user-authorization')]//input[contains(@name, 'password') and @type='password']");
            password.setValueAttribute(apitokenForTest2);
            HtmlTextInput apitoken = page.<HtmlTextInput>getFirstByXPath("//*[contains(@class, 'specific-user-authorization')]//input[contains(@name, 'apitoken') and @type='text']");
            apitoken.setValueAttribute(apitokenForTest2);
            try {
                j.submit(page.getFormByName("config"));
                fail();
            } catch (FailingHttpStatusCodeException e) {
                assertEquals(403, e.getStatusCode());
            }
        }
    }

    @Test
    public void testConfigureJobByTheUserIsAllowed() throws Exception {
        prepareSecurity();
        
        FreeStyleProject p = j.createFreeStyleProject();
        p.addProperty(new AuthorizeProjectProperty(new SpecificUsersAuthorizationStrategy("test1")));
        p.save();
        
        WebClient wc = j.createWebClient();
        wc.login("test1", "test1");
        
        j.submit(wc.getPage(p, "configure").getFormByName("config"));
    }

    @Test
    public void testConfigureJobByAnotherUserIsForbidden() throws Exception {
        prepareSecurity();
        
        FreeStyleProject p = j.createFreeStyleProject();
        p.addProperty(new AuthorizeProjectProperty(new SpecificUsersAuthorizationStrategy("test1")));
        p.save();
        
        WebClient wc = j.createWebClient();
        wc.login("test2", "test2");
        
        try {
            j.submit(wc.getPage(p, "configure").getFormByName("config"));
        } catch (FailingHttpStatusCodeException e) {
            assertEquals(403, e.getStatusCode());
        }
    }

    @Test
    public void testConfigureJobBySystemAdminIsAllowed() throws Exception {
        prepareJobBasedSecurity();
        
        FreeStyleProject p = j.createFreeStyleProject();
        p.addProperty(new AuthorizeProjectProperty(new SpecificUsersAuthorizationStrategy("test1")));
        {
            Map<Permission, Set<String>> authMap = new HashMap<>();
            authMap.put(Item.READ, Sets.newHashSet("test1"));
            authMap.put(Item.CONFIGURE, Sets.newHashSet("test1"));
            p.addProperty(new AuthorizationMatrixProperty(authMap));
        }
        p.save();
        
        WebClient wc = j.createWebClient();
        wc.login("admin", "admin");
        
        j.submit(wc.getPage(p, "configure").getFormByName("config"));
    }

    @Test
    public void testConfigureJobByJobAdminIsNotAllowed() throws Exception {
        prepareJobBasedSecurity();

        FreeStyleProject p = j.createFreeStyleProject();
        p.addProperty(new AuthorizeProjectProperty(new SpecificUsersAuthorizationStrategy("test1")));
        {
            Map<Permission, Set<String>> authMap = new HashMap<>();
            authMap.put(Item.READ, Sets.newHashSet("test1"));
            authMap.put(Item.CONFIGURE, Sets.newHashSet("test1"));
            authMap.put(Jenkins.ADMINISTER, Sets.newHashSet("test2"));
            p.addProperty(new AuthorizationMatrixProperty(authMap));
        }
        p.save();

        WebClient wc = j.createWebClient();
        wc.login("test2", "test2");

        try {
            j.submit(wc.getPage(p, "configure").getFormByName("config"));
        } catch (FailingHttpStatusCodeException e) {
            assertEquals(403, e.getStatusCode());
        }
    }
}
