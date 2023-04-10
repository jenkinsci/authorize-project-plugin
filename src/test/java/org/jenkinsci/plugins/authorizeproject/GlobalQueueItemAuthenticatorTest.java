package org.jenkinsci.plugins.authorizeproject;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;

import hudson.model.FreeStyleProject;
import hudson.model.User;
import hudson.security.ACL;
import hudson.util.DescribableList;
import jenkins.model.Jenkins;
import jenkins.security.QueueItemAuthenticator;
import jenkins.security.QueueItemAuthenticatorConfiguration;
import jenkins.security.QueueItemAuthenticatorDescriptor;
import org.jenkinsci.plugins.authorizeproject.strategy.AnonymousAuthorizationStrategy;
import org.jenkinsci.plugins.authorizeproject.strategy.SpecificUsersAuthorizationStrategy;
import org.jenkinsci.plugins.authorizeproject.testutil.AuthorizationCheckBuilder;
import org.jenkinsci.plugins.authorizeproject.testutil.AuthorizeProjectJenkinsRule;
import org.junit.Rule;
import org.junit.Test;
import org.jvnet.hudson.test.JenkinsRule;
import org.jvnet.hudson.test.JenkinsRule.WebClient;

public class GlobalQueueItemAuthenticatorTest {
    @Rule
    public JenkinsRule j = new AuthorizeProjectJenkinsRule();

    @Test
    public void testWorkForFreeStyleProject() throws Exception {
        Jenkins.get().setSecurityRealm(j.createDummySecurityRealm());

        DescribableList<QueueItemAuthenticator, QueueItemAuthenticatorDescriptor> authenticators =
                QueueItemAuthenticatorConfiguration.get().getAuthenticators();
        authenticators.remove(GlobalQueueItemAuthenticator.class);
        // if not configured, run in SYSTEM privilege.
        {
            FreeStyleProject p = j.createFreeStyleProject();
            AuthorizationCheckBuilder checker = new AuthorizationCheckBuilder();
            p.getBuildersList().add(checker);

            j.assertBuildStatusSuccess(p.scheduleBuild2(0));
            assertEquals(ACL.SYSTEM, checker.authentication);
        }

        authenticators.add(new GlobalQueueItemAuthenticator(
                new SpecificUsersAuthorizationStrategy(User.getById("bob", true).getId())));
        // if configured, GlobalQueueItemAuthenticator takes effect
        {
            FreeStyleProject p = j.createFreeStyleProject();
            AuthorizationCheckBuilder checker = new AuthorizationCheckBuilder();
            p.getBuildersList().add(checker);

            j.assertBuildStatusSuccess(p.scheduleBuild2(0));
            assertEquals("bob", checker.authentication.getPrincipal());
        }

        // if configured, AuthorizeProjectStrategy takes effect above Global as it is first in the list
        {
            ProjectQueueItemAuthenticator pqia = authenticators.get(ProjectQueueItemAuthenticator.class);
            GlobalQueueItemAuthenticator gqia = authenticators.get(GlobalQueueItemAuthenticator.class);
            assertTrue("Project is before Global", authenticators.indexOf(pqia) < authenticators.indexOf(gqia));
        }
        {
            FreeStyleProject p = j.createFreeStyleProject();
            AuthorizationCheckBuilder checker = new AuthorizationCheckBuilder();
            p.getBuildersList().add(checker);

            p.addProperty(new AuthorizeProjectProperty(new AnonymousAuthorizationStrategy()));

            j.assertBuildStatusSuccess(p.scheduleBuild2(0));
            assertEquals(Jenkins.ANONYMOUS, checker.authentication);
        }

        // if configured ProjectQueueItemAuthenticator wrong, run fall through to GlobalQueueItemAuthenticator.
        {
            FreeStyleProject p = j.createFreeStyleProject();
            AuthorizationCheckBuilder checker = new AuthorizationCheckBuilder();
            p.getBuildersList().add(checker);

            p.addProperty(new AuthorizeProjectProperty(null));

            j.assertBuildStatusSuccess(p.scheduleBuild2(0));
            assertEquals("bob", checker.authentication.getPrincipal());
        }
    }

    @Test
    public void testConfiguration() throws Exception {
        GlobalQueueItemAuthenticator auth = new GlobalQueueItemAuthenticator(new AnonymousAuthorizationStrategy());
        QueueItemAuthenticatorConfiguration.get().getAuthenticators().add(auth);

        WebClient wc = j.createWebClient();
        j.submit(wc.goTo("configureSecurity").getFormByName("config"));

        j.assertEqualDataBoundBeans(
                auth,
                QueueItemAuthenticatorConfiguration.get().getAuthenticators().get(GlobalQueueItemAuthenticator.class));
    }

    @Test
    public void testConfigurationWithDescriptorNewInstance() throws Exception {
        GlobalQueueItemAuthenticator auth =
                new GlobalQueueItemAuthenticator(new SpecificUsersAuthorizationStrategy("admin"));
        QueueItemAuthenticatorConfiguration.get().getAuthenticators().add(auth);

        WebClient wc = j.createWebClient();
        j.submit(wc.goTo("configureSecurity").getFormByName("config"));

        /*
        // as SpecificUsersAuthorizationStrategy is not annotated with @DataBoundConstructor,
        // assertEqualDataBoundBeans is not applicable.
        j.assertEqualDataBoundBeans(
                auth,
                QueueItemAuthenticatorConfiguration.get().getAuthenticators().get(GlobalQueueItemAuthenticator.class)
        );
        */
        AuthorizeProjectStrategy strategy = QueueItemAuthenticatorConfiguration.get()
                .getAuthenticators()
                .get(GlobalQueueItemAuthenticator.class)
                .getStrategy();
        assertEquals(SpecificUsersAuthorizationStrategy.class, strategy.getClass());
        assertEquals("admin", ((SpecificUsersAuthorizationStrategy) strategy).getUserid());
        // Don't care about noNeedReauthentication
        // (It might be removed for GlobalQueueItemAuthenticator in future)
    }
}
