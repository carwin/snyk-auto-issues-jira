import ForgeUI, {
  render,
  useState,
  useProductContext,
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
  TextArea,
  TextField,
} from '@forge/ui';
import api, {storage, route, webTrigger} from '@forge/api';
// import {webTrigger} from '@forge/api';

interface AppSettings {
  [jiraId: string]: {
    severityLevels: string[],
    autoCloseExternallyResolved: 'yes' | 'no'
  }
}

const initialFormState: AppSettings = {
  '10000': {
    severityLevels: ['critical', 'high'],
    autoCloseExternallyResolved: 'no',
    mappedSnykProjects: []
  }
};

// setInitialFormState()
//
// This function will get called when the form loads to prepopulate the form
// element values with data from the storage API, if available.
// If there's nothing in storage, it'll fall back to the initialFormState object.
//
// @param     string | number   The Jira project ID to look up settings for.
// @returns   object
//
const setInitialFormState: AppSettings = async(jiraProjectId: number | string) => {
  const pkey = jiraProjectId.toString();
  let settings: AppSettings | undefined = await storage.get(`${pkey}`); // @TODO.
  if (typeof(settings) === 'undefined' || settings.length === 0) {
    // Initial form state object can't possibly know about all the Jira projects
    // since we're in this condition, we know this one isn't there.
    // Copy the values from the first one onto a new key.
    settings = initialFormState[Object.keys(settings)[0]];
  }
  console.log('settings[pkey]', settings[pkey]);
  return settings;
}

// Config()
//
// Primary entry point for the configuration module
//
const Config = () => {
  const context = useProductContext();
  const [currentProjectId] = useState(context.platformContext.projectId);
  // const [formState, setFormState] = useState(storage.get('appSettings'));
  const [formState, setFormState] = useState(setInitialFormState(currentProjectId));
  const [snykWebhookInfoVisible, setSnykWebhookInfo] = useState(false);
  const [trigger] = useState(webTrigger.getUrl("snyk-webtrigger"));

  const query = useState(storage.query().getMany());

  // The onSubmit handler
  const onConfigSubmit = async(formData) => {
    // @deprecated
    // It seems like a good idea to store the Snyk Project IDs in an object with
    // the current project ID. It may make later lookups easier.
    // const mappedSnykProjectsArr = [];
    // const mappedSnykProjects = formData.mappedSnykProjects.split(',').map(item => {
    //   mappedSnykProjectsArr.push({
    //     snykProject: item.trim(),
    //     jiraProject: context.platformContext.projectId
    //   });
    // });

    console.log('--------------------------------------------------------------------------------')
    await console.log("Here's what we have in storage when we begin submit: ", await storage.get(currentProjectId))
    await storage.set(`${currentProjectId.toString()}`, formData);
    await console.log("Here's what we have in storage when we end submit: ", await storage.get(currentProjectId))
    console.log('--------------------------------------------------------------------------------')
    await storage.set(currentProjectId, formData);
    setFormState(formData);
  };

  // @TODO: The Snyk Project ID field needs a mechanism for validating.
  //        This function should correctly match UUIDs, but forge has
  //        no discernable way to implement client-side validation.
  const isUUID = (uuid) => {
    let uuidString = uuid.toString();
    uuidString = uuidString.match('/^[0-9a-f]{8}-[0-9a-f]{4}-[0-5][0-9a-f]{3}-[089ab][0-9a-f]{3}-[0-9a-f]{12}$/i');
    if (uuidString === null) {
      return false;
    }
    return true;
  }

  // Used in a <Code /> element to provide users an example
  // of how to register a webhook with Snyk.
  const snykWebhookRegistrationCommand = `curl --location --request POST 'https://snyk.io/api/v1/org/<YOUR-ORG-ID>/webhooks' \\
  --header 'Authorization: Token <YOUR-API-TOKEN>' \\
  --header 'Content-Type: application/json' \\
  --data-raw '{
      "url": "${trigger}",
      "secret": "<YOUR-CUSTOM-STRING>"
  }'`;

  // An array of button elements that appear near the Form's submit button.
  const actionButtons = [
    <Button text="Snyk Webhook Info" onClick={() => setSnykWebhookInfo(true)} />
  ]

  // This extrapolates some of the repetitive code that decides whether or not checkboxes
  // should be filled when the form loads. The idea is that the settings should persist.
  const boxCheckedOnLoad = (value) => formState.severityLevels && formState.severityLevels.includes(value) && true;
  const radioPressOnLoad = (value) => formState.autoCloseExternallyResolved === value && true;

  // This is the final return for the Config object.
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
      <Text>Which Snyk Projects are relevant to this Jira Project?</Text>
      <Text>If you wish to create Jira issues for more than one Snyk project in this Jira project, separate Snyk Project IDs using a comma <Code text="," language="bash" />.</Text>
      <Form onSubmit={onConfigSubmit} actionButtons={actionButtons}>
        <TextArea placeholder="af137b96-6966-46c1-826b-2e79ac49bbd9"
                  defaultValue={typeof(formState.mappedSnykProjects) !== 'undefined' && formState.mappedSnykProjects}
                  isRequired="true"
                  isMonospaced="true"
                  name="mappedSnykProjects"
                  label="Snyk Project ID(s)"
                  description="Insert at least one Snyk Project ID from within your Snyk Organization. Newly discovered issues on that project will be created on this board." />
        <CheckboxGroup name="severityLevels"
                       label="For which Snyk severity levels should Jira issues be created?">
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
      {formState && <Code text={JSON.stringify(formState, null, 2)} language="json" />}
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

// run()
//
// This is the entry function that the module, defined in the
// manifest, will call.
export const run = render(
  <ProjectSettingsPage>
    <Config/>
  </ProjectSettingsPage>
);


// ================================================================================
// Potentially useful things no longer in use...
// ================================================================================
//
// in one iteration I was calling storage.get for this nested
// object pretty often, but there may not be a need for it now.
//
// @TODO: This could just as easily take an argument containing the storage object
//        to avoid calling for it again if we already have it.
// const getSeverityLevelsFromStorage: string[] = async(projectId) => {
//   const settings = typeof(await storage.get(projectId) !== 'undefined')
//         ? await storage.get(projectId)
//         : initialFormState[10000];

//   let levels: array = [];

//   if (await typeof(settings.severityLevels !== undefined)) {
//     levels = settings.severityLevels;
//   }
//   return levels;
// }
