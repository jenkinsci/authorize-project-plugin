/*
 * The MIT License
 *
 * Copyright (c) 2013-2016 Stephen Connolly, IKEDA Yasuyuki
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

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.allOf;
import static org.hamcrest.Matchers.anyOf;
import static org.hamcrest.Matchers.hasProperty;
import static org.hamcrest.Matchers.instanceOf;
import static org.hamcrest.Matchers.notNullValue;
import static org.hamcrest.Matchers.nullValue;
import static org.junit.jupiter.api.Assertions.*;

import hudson.cli.CLICommandInvoker;
import hudson.model.FreeStyleProject;
import hudson.model.Item;
import hudson.model.ParametersDefinitionProperty;
import hudson.model.StringParameterDefinition;
import hudson.security.GlobalMatrixAuthorizationStrategy;
import jakarta.servlet.ServletRequest;
import java.io.ByteArrayInputStream;
import java.io.StringWriter;
import java.net.URL;
import java.util.Set;
import javax.xml.transform.Transformer;
import javax.xml.transform.TransformerException;
import javax.xml.transform.TransformerFactory;
import javax.xml.transform.dom.DOMSource;
import javax.xml.transform.stream.StreamResult;
import jenkins.model.Jenkins;
import jenkins.security.QueueItemAuthenticatorConfiguration;
import org.apache.commons.io.input.NullInputStream;
import org.htmlunit.FailingHttpStatusCodeException;
import org.htmlunit.HttpMethod;
import org.htmlunit.WebRequest;
import org.htmlunit.xml.XmlPage;
import org.jenkinsci.plugins.authorizeproject.AuthorizeProjectProperty;
import org.jenkinsci.plugins.authorizeproject.ProjectQueueItemAuthenticator;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.jvnet.hudson.test.JenkinsRule;
import org.jvnet.hudson.test.JenkinsRule.WebClient;
import org.jvnet.hudson.test.junit.jupiter.WithJenkins;
import org.jvnet.hudson.test.recipes.LocalData;
import org.w3c.dom.Document;

@WithJenkins
class SystemAuthorizationStrategyTest {

    private JenkinsRule j;

    @BeforeEach
    void setUp(JenkinsRule j) {
        this.j = j;
        QueueItemAuthenticatorConfiguration.get()
                .getAuthenticators()
                .add(new ProjectQueueItemAuthenticator(
                        Set.of(j.jenkins
                                .getDescriptor(SystemAuthorizationStrategy.class)
                                .getId()),
                        Set.of()));
    }

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
    void testGetCurrentStrategy() throws Exception {
        {
            assertNull(SystemAuthorizationStrategy.getCurrentStrategy(null));
        }
        {
            FreeStyleProject p = j.createFreeStyleProject();
            assertNull(SystemAuthorizationStrategy.getCurrentStrategy(p));
        }
        {
            FreeStyleProject p = j.createFreeStyleProject();
            p.addProperty(new ParametersDefinitionProperty(new StringParameterDefinition("foo", "bar")));
            assertNull(SystemAuthorizationStrategy.getCurrentStrategy(p));
        }
        {
            FreeStyleProject p = j.createFreeStyleProject();
            p.addProperty(new AuthorizeProjectProperty(null));
            assertNull(SystemAuthorizationStrategy.getCurrentStrategy(p));
        }
        {
            FreeStyleProject p = j.createFreeStyleProject();
            p.addProperty(new AuthorizeProjectProperty(new AnonymousAuthorizationStrategy()));
            assertNull(SystemAuthorizationStrategy.getCurrentStrategy(p));
        }
        {
            FreeStyleProject p = j.createFreeStyleProject();
            p.addProperty(new ParametersDefinitionProperty(new StringParameterDefinition("foo", "bar")));
            p.addProperty(new AuthorizeProjectProperty(new SystemAuthorizationStrategy()));
            assertThat(
                    SystemAuthorizationStrategy.getCurrentStrategy(p),
                    allOf(notNullValue(), instanceOf(SystemAuthorizationStrategy.class)));
        }
    }

    @Test
    @LocalData
    void testLoadOnStart() throws Exception {
        // verify that SystemAuthorizationStrategy is loaded correctly from the disk on startup.
        {
            FreeStyleProject p = j.jenkins.getItemByFullName("test", FreeStyleProject.class);
            assertNotNull(p);
            AuthorizeProjectProperty prop = p.getProperty(AuthorizeProjectProperty.class);
            assertNotNull(prop);
            assertThat(prop.getStrategy(), instanceOf(SystemAuthorizationStrategy.class));
        }

        j.jenkins.reload();

        // verify that SpecificUserAuthorizationStrategy is reloaded correctly from the disk.
        {
            FreeStyleProject p = j.jenkins.getItemByFullName("test", FreeStyleProject.class);
            assertNotNull(p);
            AuthorizeProjectProperty prop = p.getProperty(AuthorizeProjectProperty.class);
            assertNotNull(prop);
            assertThat(prop.getStrategy(), instanceOf(SystemAuthorizationStrategy.class));
        }
    }

    private static String getConfigXml(XmlPage page) throws TransformerException {
        // {@link XmlPage#asXml} does unnecessary indentations.
        Document doc = page.getXmlDocument();
        TransformerFactory tfactory = TransformerFactory.newInstance();
        Transformer transformer = tfactory.newTransformer();

        StringWriter sw = new StringWriter();
        transformer.transform(new DOMSource(doc), new StreamResult(sw));

        return sw.toString();
    }

    @Test
    void testRestInterfaceSuccess() throws Exception {
        prepareSecurity();

        FreeStyleProject srcProject = j.createFreeStyleProject();
        srcProject.addProperty(new AuthorizeProjectProperty(new SystemAuthorizationStrategy()));
        srcProject.save();

        WebClient wc = j.createWebClient();
        wc.login("admin");

        // GET config.xml of srcProject
        String configXml = getConfigXml(wc.goToXml("%s/config.xml".formatted(srcProject.getUrl())));

        // POST config.xml of srcProject to a new project.
        // This should success.
        FreeStyleProject destProject = j.createFreeStyleProject();
        destProject.save();
        String projectName = destProject.getFullName();

        WebRequest req = new WebRequest(
                new URL(wc.getContextPath() + "%s/config.xml".formatted(destProject.getUrl())), HttpMethod.POST);
        req.setAdditionalHeader(
                j.jenkins.getCrumbIssuer().getCrumbRequestField(),
                j.jenkins.getCrumbIssuer().getCrumb((ServletRequest) null));
        req.setRequestBody(configXml);
        wc.getPage(req);

        {
            FreeStyleProject p = j.jenkins.getItemByFullName(projectName, FreeStyleProject.class);
            assertNotNull(p);
            AuthorizeProjectProperty prop = p.getProperty(AuthorizeProjectProperty.class);
            assertThat(prop, hasProperty("strategy", instanceOf(SystemAuthorizationStrategy.class)));
        }

        j.jenkins.reload();

        {
            FreeStyleProject p = j.jenkins.getItemByFullName(projectName, FreeStyleProject.class);
            assertNotNull(p);
            AuthorizeProjectProperty prop = p.getProperty(AuthorizeProjectProperty.class);
            assertThat(prop, hasProperty("strategy", instanceOf(SystemAuthorizationStrategy.class)));
        }
    }

    @Test
    void testRestInterfaceFailure() throws Exception {
        prepareSecurity();

        FreeStyleProject srcProject = j.createFreeStyleProject();
        srcProject.addProperty(new AuthorizeProjectProperty(new SystemAuthorizationStrategy()));
        srcProject.save();

        WebClient wc = j.createWebClient();
        wc.login("test1");

        // we want to verify that you cannot clone a job even if you can reconfigure a job that uses this strategy
        j.getInstance()
                .getDescriptorByType(SystemAuthorizationStrategy.DescriptorImpl.class)
                .setPermitReconfiguration(true);

        // GET config.xml of srcProject
        String configXml = getConfigXml(wc.goToXml("%s/config.xml".formatted(srcProject.getUrl())));

        // POST config.xml of srcProject (userid is set to admin) to a new project.
        // This should fail.
        FreeStyleProject destProject = j.createFreeStyleProject();
        destProject.save();
        String projectName = destProject.getFullName();

        WebRequest req = new WebRequest(
                new URL(wc.getContextPath() + "%s/config.xml".formatted(destProject.getUrl())), HttpMethod.POST);
        req.setAdditionalHeader(
                j.jenkins.getCrumbIssuer().getCrumbRequestField(),
                j.jenkins.getCrumbIssuer().getCrumb((ServletRequest) null));
        req.setRequestBody(configXml);

        assertThrows(FailingHttpStatusCodeException.class, () -> wc.getPage(req));

        {
            FreeStyleProject p = j.jenkins.getItemByFullName(projectName, FreeStyleProject.class);
            assertNotNull(p);
            AuthorizeProjectProperty prop = p.getProperty(AuthorizeProjectProperty.class);
            assertThat(prop, anyOf(nullValue(), hasProperty("strategy", nullValue())));
        }

        j.jenkins.reload();

        {
            FreeStyleProject p = j.jenkins.getItemByFullName(projectName, FreeStyleProject.class);
            assertNotNull(p);
            AuthorizeProjectProperty prop = p.getProperty(AuthorizeProjectProperty.class);
            assertThat(prop, anyOf(nullValue(), hasProperty("strategy", nullValue())));
        }
    }

    @Test
    void testCliSuccess() throws Exception {
        prepareSecurity();

        FreeStyleProject srcProject = j.createFreeStyleProject();
        srcProject.addProperty(new AuthorizeProjectProperty(new SystemAuthorizationStrategy()));
        srcProject.save();

        WebClient wc = j.createWebClient();
        wc.login("admin");

        // GET config.xml of srcProject
        String configXml = null;
        {
            CLICommandInvoker.Result result = new CLICommandInvoker(j, "get-job")
                    .withStdin(new NullInputStream(0))
                    .asUser("admin")
                    .invokeWithArgs(srcProject.getFullName());
            configXml = result.stdout();
            String stderr = result.stderr();
            int ret = result.returnCode();

            assertEquals(0, ret, stderr);
        }

        // POST config.xml of srcProject to a new project.
        // This should success.
        FreeStyleProject destProject = j.createFreeStyleProject();
        destProject.save();
        String projectName = destProject.getFullName();

        {
            CLICommandInvoker.Result result = new CLICommandInvoker(j, "update-job")
                    .withStdin(new ByteArrayInputStream(configXml.getBytes()))
                    .asUser("admin")
                    .invokeWithArgs(destProject.getFullName());
            String stderr = result.stderr();
            int ret = result.returnCode();

            assertEquals(0, ret, stderr);
        }

        {
            FreeStyleProject p = j.jenkins.getItemByFullName(projectName, FreeStyleProject.class);
            assertNotNull(p);
            AuthorizeProjectProperty prop = p.getProperty(AuthorizeProjectProperty.class);
            assertThat(prop, hasProperty("strategy", instanceOf(SystemAuthorizationStrategy.class)));
        }

        j.jenkins.reload();

        {
            FreeStyleProject p = j.jenkins.getItemByFullName(projectName, FreeStyleProject.class);
            assertNotNull(p);
            AuthorizeProjectProperty prop = p.getProperty(AuthorizeProjectProperty.class);
            assertThat(prop, hasProperty("strategy", instanceOf(SystemAuthorizationStrategy.class)));
        }
    }

    @Test
    void testCliFailure() throws Exception {
        prepareSecurity();

        FreeStyleProject srcProject = j.createFreeStyleProject();
        srcProject.addProperty(new AuthorizeProjectProperty(new SystemAuthorizationStrategy()));
        srcProject.save();

        WebClient wc = j.createWebClient();
        wc.login("test1");

        // we want to verify that you cannot clone a job even if you can reconfigure a job that uses this strategy
        j.getInstance()
                .getDescriptorByType(SystemAuthorizationStrategy.DescriptorImpl.class)
                .setPermitReconfiguration(true);

        // GET config.xml of srcProject (userid is set to admin)
        String configXml = null;
        {
            CLICommandInvoker.Result result = new CLICommandInvoker(j, "get-job")
                    .withStdin(new NullInputStream(0))
                    .asUser("test1")
                    .invokeWithArgs(srcProject.getFullName());
            configXml = result.stdout();
            String stderr = result.stderr();
            int ret = result.returnCode();

            assertEquals(0, ret, stderr);
        }

        // POST config.xml of srcProject (userid is set to admin) to a new project.
        // This should fail.
        FreeStyleProject destProject = j.createFreeStyleProject();
        destProject.save();
        String projectName = destProject.getFullName();

        {
            CLICommandInvoker.Result result = new CLICommandInvoker(j, "update-job")
                    .withStdin(new ByteArrayInputStream(configXml.getBytes()))
                    .asUser("test1")
                    .invokeWithArgs(destProject.getFullName());
            int ret = result.returnCode();

            assertNotEquals(0, ret);
        }

        {
            FreeStyleProject p = j.jenkins.getItemByFullName(projectName, FreeStyleProject.class);
            assertNotNull(p);
            AuthorizeProjectProperty prop = p.getProperty(AuthorizeProjectProperty.class);
            assertThat(prop, anyOf(nullValue(), hasProperty("strategy", nullValue())));
        }

        j.jenkins.reload();

        {
            FreeStyleProject p = j.jenkins.getItemByFullName(projectName, FreeStyleProject.class);
            assertNotNull(p);
            AuthorizeProjectProperty prop = p.getProperty(AuthorizeProjectProperty.class);
            assertThat(prop, anyOf(nullValue(), hasProperty("strategy", nullValue())));
        }
    }

    @Test
    void testConfigurationAuthentication() throws Exception {
        prepareSecurity();

        FreeStyleProject p = j.createFreeStyleProject();

        WebClient wc = j.createWebClient();
        wc.login("test1");

        SystemAuthorizationStrategy.DescriptorImpl descriptor =
                j.getInstance().getDescriptorByType(SystemAuthorizationStrategy.DescriptorImpl.class);
        p.addProperty(new AuthorizeProjectProperty(new SystemAuthorizationStrategy()));

        // Configuration is allowed if reconfiguration is permitted.
        descriptor.setPermitReconfiguration(true);
        j.submit(wc.getPage(p, "configure").getFormByName("config"));

        // Configuration is not allowed if reconfiguration is permitted.
        descriptor.setPermitReconfiguration(false);

        FailingHttpStatusCodeException e = assertThrows(
                FailingHttpStatusCodeException.class,
                () -> j.submit(wc.getPage(p, "configure").getFormByName("config")));
        assertEquals(403, e.getStatusCode());
    }
}
