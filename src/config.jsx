import ForgeUI, {
  render,
  useState,
  Button,
  Checkbox,
  CheckboxGroup,
  Code,
  Em,
  Form,
  Fragment,
  Heading,
  Link,
  ModalDialog,
  Option,
  ProjectSettingsPage,
  RadioGroup,
  Radio,
  SectionMessage,
  Select,
  Strong,
  Text,
  TextField,
} from '@forge/ui';
import {storage} from '@forge/api';
import {webTrigger} from '@forge/api';

interface AppSettings {
  severityLevels: string[],
  autoCloseExternallyResolved: 'yes' | 'no'
}

const initialFormState: AppSettings = {
  appSettings: {
    severityLevels: ['critical', 'high'],
    autoCloseExternallyResolved: 'no'
  }
};

// If there's nothing in storage, use the default object.
const setInitialFormState: AppSettings = async() => {
  let settings: AppSettings | undefined = await storage.get('appSettings');
  if (typeof(settings) === 'undefined' || settings.length === 0) {
    settings = initialFormState;
  }

  return settings;
}

// Possibly useful, in one iteration I was calling storage.get for this nested
// object pretty often, but there may not be a need for it now.
//
// @TODO: This could just as easily take an argument containing the storage object
//        to avoid calling for it again if we already have it.
const getSeverityLevelsFromStorage: string[] = async() => {
  const settings = typeof(await storage.get('appSettings') !== 'undefined')
        ? await storage.get('appSettings')
        : initialFormState;

  let levels: array = [];

  if (await typeof(settings.severityLevels !== undefined)) {
    levels = settings.severityLevels;
    // levels = settings.severityLevels;
  }
  return levels;
}

// const getJiraWebTriggerURLForRegistration = async() => {
//   const [trigger] = await webTrigger.getUrl("snyk-webtrigger");
//   return trigger;
// }

// Primary entry point for the configuration module
const Config = () => {
  const [formState, setFormState] = useState(storage.get('appSettings'));
  const [snykWebhookInfoVisible, setSnykWebhookInfo] = useState(false);
  const [trigger] = useState(webTrigger.getUrl("snyk-webtrigger"));

  // Startup messages for development.
  // @TODO: Remove
  // console.log("COMPLETE APP CONFIG FROM STORAGE: ", useState(storage.get('appSettings')));
  // console.log("STORED SEV LEVELS: ", useState(getSeverityLevelsFromStorage()));
  // console.log("FALLBACK FORM STATE: ", initialFormState);
  // console.log("CURRENT FORM STATE: ", formState);

  const onConfigSubmit = async(formData) => {
    console.log('Here is the formData: ', formData);
    await storage.set('appSettings', formData);
    setFormState(formData);
    await console.log("Here's what we have in storage: ", await storage.get('appSettings'))
  };

  const snykWebhookRegistrationCommand = `curl --location --request POST 'https://snyk.io/api/v1/org/<YOUR-ORG-ID>/webhooks' \\
  --header 'Authorization: Token <YOUR-API-TOKEN>' \\
  --header 'Content-Type: application/json' \\
  --data-raw '{
      "url": "${trigger}",
      "secret": "<YOUR-CUSTOM-STRING>"
  }'`;

  const actionButtons = [
    <Button text="Snyk Webhook Info" onClick={() => setSnykWebhookInfo(true)} />
  ]

  // This extrapolates some of the repetitive code that decides whether or not checkboxes
  // should be filled when the form loads. The idea is that the settings should persist.
  const boxCheckedOnLoad = (value) => formState.severityLevels.includes(value) && true;
  const radioPressOnLoad = (value) => formState.autoCloseExternallyResolved === value && true;

  return (
    <Fragment>
      <Heading size="large">About</Heading>
      <Text>
        The Snyk POC Jira Application subscribes to a Snyk organization's project scan results, automatically creating
        Jira issues for <Strong>newly reported</Strong> vulnerabilities.</Text>
      <SectionMessage>
        <Text>
        <Em>It is important to note that this application watches <Strong>all</Strong> the projects within a given Snyk
        Organization. For users that wish to limit issues created for this Jira project to a particular <Strong>project</Strong> within
        Snyk, we recommend <Link href="https://docs.snyk.io/features/user-and-group-management/managing-groups-and-organizations/manage-snyk-organizations">creating a new Snyk Organization</Link>
         to house it.</Em>
        </Text>
      </SectionMessage>
      <Heading size="medium">Before you begin</Heading>
      <Text>
        This Jira Application functions by consuming a Webhook from <Link href="https://snyk.io">Snyk</Link>.
        Webhooks require both a provider and a consumer to work properly. In the context of Webhooks, this Jira App
        acts as the <Em>consumer</Em>. To complete the configuration, Snyk must be informed that there is a new
        consumer to which Webhook events should be sent.
      </Text>
      <Text>
        Informing Snyk (the provider) about the new consumer is a relatively simple process. You can review the
        official Snyk documentation <Strong><Link href="https://docs.snyk.io/integrations/snyk-webhooks#snyk-webhooks-for-snyk-api">here</Link></Strong>.
      </Text>
      <Text>
        The necessary information about this consumer can be found by clicking the <Em>Snyk Webhook Info</Em> button at the
        bottom of this page. The resulting modal window also contains an example cURL request you can use, but be sure to
        replace the sample values with your desired Snyk Organization ID and your API Token.
      </Text>
      <Heading size="large">Configuration</Heading>
      <Heading size="medium">Automatic Issue Creation</Heading>
      <Text>For which Snyk severity levels should Jira issues be created?</Text>
      <Form onSubmit={onConfigSubmit} actionButtons={actionButtons}>
        <CheckboxGroup name="severityLevels">
          <Checkbox value="critical" label="Critical" defaultChecked={boxCheckedOnLoad('critical')} />
          <Checkbox value="high" label="High" defaultChecked={boxCheckedOnLoad('high')} />
          <Checkbox value="medium" label="Medium" defaultChecked={boxCheckedOnLoad('medium')} />
          <Checkbox value="low" label="Low" defaultChecked={boxCheckedOnLoad('low')} />
        </CheckboxGroup>
        <Heading size="medium">Automatic Issue Resolution</Heading>
        <Text>When a previously reported Snyk issue has been resolved, the Snyk POC Jira App can automatically close the corresponding issue it created in Jira.</Text>
        <RadioGroup isRequired="true"
                    label="Close Jira issues when Snyk reports the issue resolved?"
                    name="autoCloseExternallyResolved"
                    value="close">
          <Radio label="Do not automatically close Jira issues" value="no" defaultChecked={radioPressOnLoad('no')} />
          <Radio label="Automatically close externally remediated Jira issues" value="yes" defaultChecked={radioPressOnLoad('yes')} />
        </RadioGroup>
      </Form>
      {formState && <Text>{JSON.stringify(formState)}</Text>}
      {snykWebhookInfoVisible && (
        <ModalDialog header="Connecting to Snyk" onClose={() => setSnykWebhookInfo(false)}>
          <Text>Reference the information on this page When registering this App as a Webhook consumer with Snyk.</Text>
          <Heading size="small">Snyk Webhook Callback URL</Heading>
          <Text>Use this URL when registering the webhook with Snyk.</Text>
          <Code text={trigger.toString()} language="rust" />
          <Heading size="small">Registering a webhook with cURL</Heading>
          <Code text={snykWebhookRegistrationCommand} language="bash" />
        </ModalDialog>
      )}
    </Fragment>
  );
};

export const run = render(
  <ProjectSettingsPage>
    <Config/>
  </ProjectSettingsPage>
);
