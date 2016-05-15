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
import java.util.Arrays;
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
import hudson.security.GlobalMatrixAuthorizationStrategy;

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
import com.gargoylesoftware.htmlunit.WebRequestSettings;
import com.gargoylesoftware.htmlunit.html.HtmlCheckBoxInput;
import com.gargoylesoftware.htmlunit.html.HtmlPage;
import com.gargoylesoftware.htmlunit.html.HtmlPasswordInput;
import com.gargoylesoftware.htmlunit.html.HtmlTextInput;
import com.gargoylesoftware.htmlunit.xml.XmlPage;

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
    public void testDescriptorAuthenticateWithApitoken() throws Exception {
        prepareSecurity();
        String apitokenForTest1 = User.get("test1").getProperty(ApiTokenProperty.class).getApiToken();
        
        AuthenticateDescriptorImpl d = new AuthenticateDescriptorImpl();
        assertTrue(d.authenticateWithApitoken(new SpecificUsersAuthorizationStrategy("test1", false), apitokenForTest1));
        assertFalse(d.authenticateWithApitoken(new SpecificUsersAuthorizationStrategy("test1", false), apitokenForTest1 + "xxx"));
        assertFalse(d.authenticateWithApitoken(new SpecificUsersAuthorizationStrategy("test1", false), ""));
        assertFalse(d.authenticateWithApitoken(new SpecificUsersAuthorizationStrategy("", false), apitokenForTest1));
        assertFalse(d.authenticateWithApitoken(new SpecificUsersAuthorizationStrategy("test1", false), null));
        assertFalse(d.authenticateWithApitoken(new SpecificUsersAuthorizationStrategy(null, false), apitokenForTest1));
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
        p.addProperty(new AuthorizeProjectProperty(new SpecificUsersAuthorizationStrategy("validuser", false)));
        
        j.assertBuildStatusSuccess(p.scheduleBuild2(0).get(1, TimeUnit.SECONDS));
        assertEquals("validuser", checker.authentication.getName());
        
        // In case of specifying an invalid user,
        // falls back to anonymous.
        // And the build should not be blocked.
        p.removeProperty(AuthorizeProjectProperty.class);
        p.addProperty(new AuthorizeProjectProperty(new SpecificUsersAuthorizationStrategy("invaliduser", false)));
        
        j.assertBuildStatusSuccess(p.scheduleBuild2(0).get(1, TimeUnit.SECONDS));
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
        srcProject.addProperty(new AuthorizeProjectProperty(new SpecificUsersAuthorizationStrategy("test1", false)));
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
        
        WebRequestSettings req = new WebRequestSettings(
                wc.createCrumbedUrl(String.format("%s/config.xml", destProject.getUrl())),
                HttpMethod.POST
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
        srcProject.addProperty(new AuthorizeProjectProperty(new SpecificUsersAuthorizationStrategy("admin", false)));
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
        
        WebRequestSettings req = new WebRequestSettings(
                wc.createCrumbedUrl(String.format("%s/config.xml", destProject.getUrl())),
                HttpMethod.POST
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
        srcProject.addProperty(new AuthorizeProjectProperty(new SpecificUsersAuthorizationStrategy("test1", false)));
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
        srcProject.addProperty(new AuthorizeProjectProperty(new SpecificUsersAuthorizationStrategy("admin", false)));
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
    public void testConfigurationAuthentication() throws Exception {
        prepareSecurity();
        
        FreeStyleProject p = j.createFreeStyleProject();
        
        WebClient wc = j.createWebClient();
        wc.login("test1");
        
        // Reauthentication is not required if No need for re-authentication is checked
        p.addProperty(new AuthorizeProjectProperty(new SpecificUsersAuthorizationStrategy("admin", true)));
        j.submit(wc.getPage(p, "configure").getFormByName("config"));
        
        // Reauthentication is required if No need for re-authentication is checked
        p.removeProperty(AuthorizeProjectProperty.class);
        p.addProperty(new AuthorizeProjectProperty(new SpecificUsersAuthorizationStrategy("admin", false)));
        try {
            j.submit(wc.getPage(p, "configure").getFormByName("config"));
            fail();
        } catch (FailingHttpStatusCodeException e) {
            assertEquals(400, e.getStatusCode());
        }
        
        // No authentication is required if oneself.
        {
            HtmlPage page = wc.getPage(p, "configure");
            HtmlTextInput userid = page.<HtmlTextInput>getFirstByXPath("//*[contains(@class, 'specific-user-authorization')]//input[contains(@name, 'userid') and @type='text']");
            userid.setValueAttribute("test1");
            j.submit(page.getFormByName("config"));
            
            assertEquals("test1", ((SpecificUsersAuthorizationStrategy)p.getProperty(AuthorizeProjectProperty.class).getStrategy()).getUserid());
        }
        
        // Reauthentication is required to change userid even if No need for re-authentication is checked
        p.addProperty(new AuthorizeProjectProperty(new SpecificUsersAuthorizationStrategy("admin", true)));
        {
            HtmlPage page = wc.getPage(p, "configure");
            HtmlTextInput userid = page.<HtmlTextInput>getFirstByXPath("//*[contains(@class, 'specific-user-authorization')]//input[contains(@name, 'userid') and @type='text']");
            userid.setValueAttribute("test2");
            try {
                j.submit(page.getFormByName("config"));
                fail();
            } catch (FailingHttpStatusCodeException e) {
                assertEquals(400, e.getStatusCode());
            }
        }
    }
    
    @Test
    public void testConfigurePassword() throws Exception {
        prepareSecurity();
        
        FreeStyleProject p = j.createFreeStyleProject();
        p.addProperty(new AuthorizeProjectProperty(new SpecificUsersAuthorizationStrategy("test2", false)));
        
        WebClient wc = j.createWebClient();
        wc.login("test1");
        
        // authentication fails without password
        {
            HtmlPage page = wc.getPage(p, "configure");
            HtmlCheckBoxInput useApitoken = page.<HtmlCheckBoxInput>getFirstByXPath("//*[contains(@class, 'specific-user-authorization')]//input[contains(@name, 'useApitoken') and @type='checkbox']");
            useApitoken.setChecked(false);
            try {
                j.submit(page.getFormByName("config"));
                fail();
            } catch (FailingHttpStatusCodeException e) {
                assertEquals(400, e.getStatusCode());
            }
        }
        
        // authentication succeeds with the good password
        {
            HtmlPage page = wc.getPage(p, "configure");
            HtmlCheckBoxInput useApitoken = page.<HtmlCheckBoxInput>getFirstByXPath("//*[contains(@class, 'specific-user-authorization')]//input[contains(@name, 'useApitoken') and @type='checkbox']");
            useApitoken.setChecked(false);
            HtmlPasswordInput password = page.<HtmlPasswordInput>getFirstByXPath("//*[contains(@class, 'specific-user-authorization')]//input[contains(@name, 'password') and @type='password']");
            password.setValueAttribute("test2");
            j.submit(page.getFormByName("config"));
            
            assertEquals("test2", ((SpecificUsersAuthorizationStrategy)p.getProperty(AuthorizeProjectProperty.class).getStrategy()).getUserid());
        }
        
        // authentication fails with a bad password
        {
            HtmlPage page = wc.getPage(p, "configure");
            HtmlCheckBoxInput useApitoken = page.<HtmlCheckBoxInput>getFirstByXPath("//*[contains(@class, 'specific-user-authorization')]//input[contains(@name, 'useApitoken') and @type='checkbox']");
            useApitoken.setChecked(false);
            HtmlPasswordInput password = page.<HtmlPasswordInput>getFirstByXPath("//*[contains(@class, 'specific-user-authorization')]//input[contains(@name, 'password') and @type='password']");
            password.setValueAttribute("badpassword");
            try {
                j.submit(page.getFormByName("config"));
                fail();
            } catch (FailingHttpStatusCodeException e) {
                assertEquals(400, e.getStatusCode());
            }
        }
        
        // authentication fails if the password is used for apitoken
        {
            HtmlPage page = wc.getPage(p, "configure");
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
                assertEquals(400, e.getStatusCode());
            }
        }
    }
    
    @Test
    public void testConfigureApitoken() throws Exception {
        prepareSecurity();
        
        FreeStyleProject p = j.createFreeStyleProject();
        p.addProperty(new AuthorizeProjectProperty(new SpecificUsersAuthorizationStrategy("test2", false)));
        
        WebClient wc = j.createWebClient();
        wc.login("test1");
        
        String apitokenForTest2 = User.get("test2").getProperty(ApiTokenProperty.class).getApiToken();
        assertNotNull(apitokenForTest2);
        assertNotEquals("", apitokenForTest2);
        
        // authentication fails without apitoken
        {
            HtmlPage page = wc.getPage(p, "configure");
            HtmlCheckBoxInput useApitoken = page.<HtmlCheckBoxInput>getFirstByXPath("//*[contains(@class, 'specific-user-authorization')]//input[contains(@name, 'useApitoken') and @type='checkbox']");
            useApitoken.setChecked(true);
            try {
                j.submit(page.getFormByName("config"));
                fail();
            } catch (FailingHttpStatusCodeException e) {
                assertEquals(400, e.getStatusCode());
            }
        }
        
        // authentication succeeds with the good apitoken
        {
            HtmlPage page = wc.getPage(p, "configure");
            HtmlCheckBoxInput useApitoken = page.<HtmlCheckBoxInput>getFirstByXPath("//*[contains(@class, 'specific-user-authorization')]//input[contains(@name, 'useApitoken') and @type='checkbox']");
            useApitoken.setChecked(true);
            HtmlTextInput apitoken = page.<HtmlTextInput>getFirstByXPath("//*[contains(@class, 'specific-user-authorization')]//input[contains(@name, 'apitoken') and @type='text']");
            apitoken.setValueAttribute(apitokenForTest2);
            j.submit(page.getFormByName("config"));
            
            assertEquals("test2", ((SpecificUsersAuthorizationStrategy)p.getProperty(AuthorizeProjectProperty.class).getStrategy()).getUserid());
        }
        
        // authentication fails with a bad apitoken
        {
            HtmlPage page = wc.getPage(p, "configure");
            HtmlCheckBoxInput useApitoken = page.<HtmlCheckBoxInput>getFirstByXPath("//*[contains(@class, 'specific-user-authorization')]//input[contains(@name, 'useApitoken') and @type='checkbox']");
            useApitoken.setChecked(true);
            HtmlTextInput apitoken = page.<HtmlTextInput>getFirstByXPath("//*[contains(@class, 'specific-user-authorization')]//input[contains(@name, 'apitoken') and @type='text']");
            apitoken.setValueAttribute(apitokenForTest2 + "xxx");
            try {
                j.submit(page.getFormByName("config"));
                fail();
            } catch (FailingHttpStatusCodeException e) {
                assertEquals(400, e.getStatusCode());
            }
        }
        
        // authentication fails if the apitoken is used for password
        {
            HtmlPage page = wc.getPage(p, "configure");
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
                assertEquals(400, e.getStatusCode());
            }
        }
    }
}
