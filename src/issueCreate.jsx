import ForgeUI, {
  render,
  Fragment,
  Text,
  ProjectSettingsPage,
  IssuePanel,
  useProductContext,
  useState } from '@forge/ui';
import api, {fetch, storage, startsWith, route} from '@forge/api';
import * as md2adf from 'md-to-adf';

interface JiraIssue {
  update: {},
  fields: {
    summary: string,
    issueType:  {
      id: number
    },
    project: {
      id: number
    },
    description: {
      type: string,
      version: number,
      content: {text: string, type: string}[]
    },
    labels: string[]
  }
}

// Issues in the response will show up in the following objects:
// - body.newIssues
// - body.removedIssues
//
// The project snapshot event does NOT contain information about already known vulnerabilities.
//
// This listener function is called when the webtrigger is invoked, meaning
// whenever Snyk sends a Webhook event.
export const processSnykHookData = async(req) => {
  // We'll need to loop through the storage data to find the appropriate Jira project to use
  // when we open a new issue. Unfortunately, the Storage API only allows queries to target
  // the `key`, so this could get a little ugly...
  const storageData = await storage.query().getMany();


  console.log('++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++');
  console.log('storageData in processSnykHook(): ', storageData);
  //storageData.results.map(jiraProjectSettings => console.log(jiraProjectSettings.value))
  console.log('++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++');

  const context = useProductContext();

  try {
    // Capture the various response bits and bobs as variables.
    const body = JSON.parse(req.body);
    const snykProjectId = body.project.id;
    const snykProjectName = body.project.name;
    let newIssueCount = body.newIssues.length;
    const removedIssueCount = body.removedIssues.length;
    const dependencyCount = body.project.totalDependencies;
    const issueCountCritical = body.project.issueCountsBySeverity.critical;
    const eventType = req.headers['x-snyk-event'];

    console.log(`Snyk webhook incoming...`);
    await console.log(`This one's event type is: ${eventType}.`);

    // ***********
    // * Step 1  * - Confirm the received event type.
    // ***********

    // We're only interested in this event type.
    // Conveniently, this is the only event type that Snyk sends out right now.
    if (eventType == 'project_snapshot/v0') {
      // @TODO: Remove logging.
      await console.log(`${snykProjectName} was tested`);
      await console.log(`It's ID is: ${snykProjectId}`);
      await console.log(`This project has ${dependencyCount} dependencies.`);
      await console.log(`There are ${issueCountCritical} CRITICAL issues.`);
      await console.log(`Wow! There are ${newIssueCount} new issues.`);
      await console.log(`${removedIssueCount} issues were removed/remediated since the previous scan.`);
      await console.log(`---------------------------------`)
      await console.log('We should maybe create Jira issues for the issues Snyk reports...');


      // ***********
      // * Step 2  * - Determine whether the payload's Snyk project has been mapped to a Jira project by the user.
      // ***********

      // `appConfigs` contains only storage data with a `mappedSnykProjects`
      //   array. In production this is likely unnecessary since the app storage
      //   won't be cluttered with development artifacts, but it won't hurt
      //   anything to leave it in.
      const appConfigs = storageData.results
                                    .filter(item => typeof(item.value.mappedSnykProjects) !== 'undefined' && Array.isArray(item.value.mappedSnykProjects));
      // - `mappedAppConfig` contains an app configuration for the Snyk project
      //   ID related to the webhook Event currently being evaluated OR it
      //   returns undefined if a matching configuration couldn't be found.
      const mappedAppConfig = appConfigs.filter(p => p.value.mappedSnykProjects.includes(snykProjectId.toString()));
      // - A simple boolean in case we need one. Confirms that there is a mapping.
      const jiraMappingExists = mappedAppConfig.length > 0;
      // - Contains the Jira project ID that this Event's Snyk project has been
      //   mapped to by the user.
      // @TODO: See config.jsx - We call the first array key intentionally to
      //        prevent the creation of Jira issues in multiple Jira projects.
      const matchingJiraProjectId = mappedAppConfig[0] ? mappedAppConfig[0].key : false;
      const newIssueType = mappedAppConfig[0] ? mappedAppConfig[0].value.issueType : false;
      const severityConditions = mappedAppConfig[0] ? mappedAppConfig[0].value.severityLevels : [];

      // We'll stop here if there is no mapped Jira project for this event's Snyk project
      if (typeof mappedAppConfig === 'undefined' || mappedAppConfig.length <= 0) {
        console.log('This Snyk project has not been configured within the app settings. Aborting.');
        return false;
      }

      // ***********
      // * Step 3  * - Prepare an array of objects representing new Jira Issues
      // ***********

      // Instantiate a new array to collect/arrange the data.
      const newIssueData = [];

      // Operate only when newIssueCount isn't 0.
      if (newIssueCount > 0) {
        for(let i = 0; i < newIssueCount; i++) {
          const issueData = body.newIssues[i].issueData;
          const exists = await issueExistsInJira({snykIssueId: issueData.id});
          const existingIssueIdent = await issueExistsInJira({snykIssueId: issueData.id, returnIssueIfTrue: true});

          console.log(`Issue already exists?: ${exists}`);
          console.log(`Issue severity: ${issueData.severity}`);
          console.log(`App severity settings: ${severityConditions}`);

          // Push the data into newIssueData array only if an existing issue is not present
          // and the severity level of the issue matches this app's severity level settings.
          if (!exists && severityConditions.includes(issueData.severity)) {
            newIssueData.push({snykProject: snykProjectName,
                               snykIssueId: issueData.id,
                               snykIssueTitle: issueData.title,
                               // snykDescription: markdownToAtlassianWikiMarkup(issueData.description),
                               snykDescription: issueData.description,
                               snykSeverity: issueData.severity,
                               snykUrl: issueData.url,
                               jiraProjectId: matchingJiraProjectId,
                               jiraIssueTypeId: newIssueType});
            }
          }
      }

      // ***********
      // * Step 4  * - Create new issues in Jira
      // ***********

      console.log('length of new issue data: ', newIssueData.length);
      if (newIssueData.length > 0) {
        // Here we go...
        newIssueData.map(issue => {
          const preparedIssue = prepareNewIssue(issue);
          console.log('preparedIssue: ', preparedIssue);
          createJiraIssue({data: preparedIssue});
        });
      }

      return {
        body: "Success: Jira issues created for updated Snyk Project \n",
        headers: { "Content-Type": ["application/json"] },
        statusCode: 200,
        statusText: "OK",
      };

    }
  } catch (error) {
    console.log("It doesn't work", error);
    return {
      body: error + "\n",
      headers: { "Content-Type": ["application/json"] },
      statusCode: 400,
      statusText: "Bad Request",
    }
  }
}

// Returns an object with issue key and ID if there's already a Jira Issue opened
// for a given Snyk issue.
//
// For now, we'll use Jira issue labels to keep track of our issues.
// This is not ideal.
const issueExistsInJira = async({snykIssueId, returnIssueIfTrue = false} : {string, boolean}) => {
  // Construct the label to look up.
  // The format comes from prepareNewIssue().

  const issueLabel = `snykId-${snykIssueId}`;
  const searchResult = await findJiraIssue(issueLabel);

  if (typeof searchResult.issues !== 'undefined' && searchResult.issues.length > 0) {
    if (returnIssueIfTrue === true) {
      return {
        key: await searchResult.issues[0].key,
        id: await searchResult.issues[0].id
      }
    }
    return true;
  }

  return false;
};

// Search for a Jira issue
//
// Takes a single string argument representing JQL text.
const findJiraIssue = async(query) => {
  const context = useProductContext();

  const encodedQuery = encodeURIComponent(query);
  console.log('Encoded Query: ', encodedQuery);
  const response = await api.asApp().requestJira(route`/rest/api/3/search?jql=labels%20%3D%20${query}`, {
  // bonst response = api.asApp().requestJira(route`/rest/api/3/issue/picker?query=${query}`, {
    method: "GET",
    headers: {
      'Accept': 'application/json',
      'Content-Type': 'application/json'
    },
  })
  .then(res => {
     console.log(`Response: ${res.status} ${res.statusText}`)
     return res.json();
  })
  .catch(err => console.error(err));

  return response;
}

// To match the existing Jira integration, all we really need is:
//  1. issue.issueData.title
//  2. issue.issueData.url
//  3. issue.issueData.description
const prepareNewIssue = ({snykProject, snykIssueId, snykIssueTitle, snykDescription, snykSeverity, snykUrl, jiraProjectId, jiraIssueTypeId} : {string, string, string, string, string, string, string, number}) => {

  console.log('==========================================');
  console.log(`Preparing a new Jira issue from Snyk data...`);
  console.log(`snykProject - ${snykProject}`);
  console.log(`snykIssueId - ${snykIssueId}`);
  console.log(`snykIssueTitle - ${snykIssueTitle}`);
  console.log(`snykSeverity - ${snykSeverity}`);
  console.log(`snykUrl - ${snykUrl}`);
  console.log(`jiraProjectId - ${jiraProjectId}`);
  console.log(`jiraIssueType - ${jiraIssueTypeId}`);
  console.log('==========================================');


  // Body data needs to return a _string_ of JSON.
  // The Jira V3 API supports Atlassian Document Format, so our source Markdown has to be converted.
  const bodyData = {
    update: {},
    fields: {
      summary: snykIssueTitle,
      issuetype: {
        id: jiraIssueTypeId
      },
      project: {
        id: jiraProjectId
      },
      description: md2adf(snykDescription),
      labels: [
        'snyk',
        `snykSev-${snykSeverity}`,
        `snykId-${snykIssueId}`
      ]
    }
  };
  return bodyData;
}

const createJiraIssue = async({data} : {any}) => {
  console.log('createJiraIssue() called. Creating issue...');
  const context = useProductContext();
  const response = await api
        .asApp()
        .requestJira(route`/rest/api/3/issue/`, {
    method: "POST",
    headers: {
      'Accept': 'application/json',
      'Content-Type': 'application/json'
    },
    body: JSON.stringify(data)
  });
  console.log(`Response: ${response.status} ${response.statusText}`);
  const result = await response.json();

  return result;
}

// Helper function
export const getDataFromJira = async url => {
  try {
    const response = await api.asApp().requestJira(route`${url}`);
    const result = await response.json();
    return result;
  } catch (error) {
    console.log("getDataFromJira() error: ", error);
    throw error;
  }
};
