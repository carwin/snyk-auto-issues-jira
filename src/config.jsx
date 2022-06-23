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
  }
}

const initialFormState: AppSettings = {
  '10000': {
    severityLevels: ['critical', 'high'],
    mappedSnykProjects: [],
    issueType: '',
  }
};

const getProjectIssueTypes = async() => {
  const response = await api
        .asApp()
        .requestJira(route`/rest/api/3/issuetype`);
  const result = await response.json();
  const optionComponents = await projectIssueTypesToFormOptions(result);
  return optionComponents;
}

const projectIssueTypesToFormOptions = (rawTypes) => {
  const context = useProductContext();
  console.log(`Got ${rawTypes.length} raw types`);
  const options = [];

  if (rawTypes.length > 0) {
    rawTypes.map(type => {
      if (type.scope.project.id === context.platformContext.projectId) {
        type.subtask !== true ? options.push(<Option label={type.name} value={type.id} __auxId={`Option.${type.id}`} />) : false;
        // type.subtask !== true ? options.push(<Option label={type.name} value={type.id} defaultSelected={optionSelectOnLoad(type.id)} />) : false;
        // type.subtask !== true ? options.push({name: type.name, value: type.id}) : false;
      }
    })
  }
  console.log('options', options);
  return options;
}

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
  // @TODO: List is below
  // Validate that submitted SNYK project IDs are valid UUIDs.
  // - Validate the content of that field on form submit.
  // - Show an error of some kind, explaining the problem.
    console.log('formData on submit... ', formData);
    console.log('formState on submit...', formState);

    const mappedSnykProjectsArray: string[] = [];
    if (typeof formData.mappedSnykProjects !== 'undefined' && formData.mappedSnykProjects.includes(',')) {
      formData.mappedSnykProjects = formData.mappedSnykProjects.split(',').map(item => item.trim());
    }

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
      "secret": "<YOUR-CUSTOM-TEXT>"
  }'`;

  const [issueTypeOptions] = useState(async() => await getProjectIssueTypes());

  // This extrapolates some of the repetitive code that decides whether or not checkboxes
  // should be filled when the form loads. The idea is that the settings should persist.
  const boxCheckedOnLoad = (value) => formState.severityLevels && formState.severityLevels.includes(value) && true;
  const optionSelectOnLoad = (value) => formState.issueType === value && true;

  // This is the final return for the Config object.
  return (
    <Fragment>
      <Heading size="large">About</Heading>
      <Text>
        The Snyk Auto-Issues for Jira application subscribes to a Snyk organization's project scan results, automatically creating
        Jira issues for <Strong>newly reported</Strong> vulnerabilities. Use the form below to configure the operation of this
        Jira application.</Text>
      <Heading size="medium">Before you begin</Heading>
      <Text>
        This Jira application functions by consuming a webhook from <Link href="https://snyk.io">Snyk</Link>.
        Webhooks require both a provider and a consumer to work properly. In the context of webhooks, this Jira application
        acts as the <Em>consumer</Em>. To complete the configuration, a Snyk webhook must be created which points to this
        application as the consumer to which scan results should be sent.
      </Text>
      <SectionMessage>
        <Text>
          <Strong>Note:</Strong> The features necessary for this application to function are available only to Paid and Enterprise Snyk customers.
        </Text>
        <Text>
          <Link href="https://app.snyk.io/login">Sign up for a new Snyk account</Link>
        </Text>
      </SectionMessage>

      <Text>
        Creating a new Snyk webhook is a relatively simple process. Review the official Snyk documentation,
        <Strong><Link href="https://docs.snyk.io/integrations/snyk-webhooks#snyk-webhooks-for-snyk-api"> here</Link></Strong>, for
        a complete overview.
      </Text>
      <Text>
        The necessary information about this consumer can be found by clicking the <Em>Snyk Webhook Info</Em> button below.
        The resulting modal window contains this application's callback URL as well as an example cURL request which can be used
        to quickly get up and running.
      </Text>
      <Button text="Snyk Webhook Info" onClick={() => setSnykWebhookInfo(true)} />

      <Heading size="large">Configuration</Heading>
      <Form onSubmit={onConfigSubmit}>

        <Heading size="medium">Snyk Project Settings</Heading>
        <Text>Insert the unique project ID of the Snyk project(s) to be monitored.</Text>
        <Text>
          Information on locating a project's unique ID may be found: <Strong><Link href="https://docs.snyk.io/introducing-snyk/introduction-to-snyk-projects/view-project-settings">here</Link></Strong>.
          If you wish to create Jira issues for more than one Snyk project, separate the unique Snyk project IDs using a comma <Code text="," language="bash" />.
        </Text>
        <TextArea placeholder="af137b96-6966-46c1-826b-2e79ac49bbd9"
                  defaultValue={typeof(formState.mappedSnykProjects) !== 'undefined' && formState.mappedSnykProjects}
                  isRequired="true"
                  isMonospaced="true"
                  name="mappedSnykProjects"
                  label="Snyk Project ID(s)"
                  description="Insert at least one Snyk Project ID from within your Snyk Organization. Newly discovered issues on that project will be created on this board." />

        <Heading size="medium">Severity Level Options</Heading>
        <Text>
          The options below provide a mechanism for limiting the automated Jira issue creation by severity.
        </Text>
        <CheckboxGroup name="severityLevels"
                       label="Select the severity levels for which Jira issues will be created.">
          <Checkbox value="critical" label="Critical" defaultChecked={boxCheckedOnLoad('critical')} />
          <Checkbox value="high" label="High" defaultChecked={boxCheckedOnLoad('high')} />
          <Checkbox value="medium" label="Medium" defaultChecked={boxCheckedOnLoad('medium')} />
          <Checkbox value="low" label="Low" defaultChecked={boxCheckedOnLoad('low')} />
        </CheckboxGroup>

        <Heading size="medium">Jira Issue Settings</Heading>
        <Text>
          New issues can be created as one of the issue types defined in this Jira project. Select the issue type below.
        </Text>
        <Select isRequired="true" label="Issue type for automated issue creation" name="issueType">
          {issueTypeOptions.map((type) => {
            type.props.defaultSelected = optionSelectOnLoad(type.props.value)
            return type
          })}
        </Select>
      </Form>
      {snykWebhookInfoVisible && (
        <ModalDialog header="Connecting to Snyk" onClose={() => setSnykWebhookInfo(false)}>
          <Text>Reference the information on this page when creating a Snyk webhook.</Text>
          <Heading size="small">Snyk Webhook Callback URL</Heading>
          <Text>The URL below is unique to this Jira project.</Text>
          <Code text={trigger.toString()} language="rust" />
          <Heading size="small">Registering a webhook with cURL</Heading>
          <Text>
            For convenience, this cURL request should take care of configuring a webhook for this application. <Strong>Be sure to
            replace the sample values with your desired Snyk Organization ID and your API Token</Strong>.
          </Text>
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
