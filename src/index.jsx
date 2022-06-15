//////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

const fakeProject = {
  "project": {
  "name": "snyk/goof",
  "id": "af137b96-6966-46c1-826b-2e79ac49bbd9",
  "created": "2018-10-29T09:50:54.014Z",
  "origin": "github",
  "type": "maven",
  "readOnly": false,
  "testFrequency": "daily",
  "totalDependencies": 42,
  "issueCountsBySeverity": {
    "low": 13,
    "medium": 8,
    "high": 4,
    "critical": 5
  },
  "imageId": "sha256:caf27325b298a6730837023a8a342699c8b7b388b8d878966b064a1320043019",
  "imageTag": "latest",
  "imageBaseImage": "alpine:3",
  "imagePlatform": "linux/arm64",
  "imageCluster": "Production",
  "hostname": null,
  "remoteRepoUrl": "https://github.com/snyk/goof.git",
  "lastTestedDate": "2019-02-05T08:54:07.704Z",
  "browseUrl": "https://app.snyk.io/org/4a18d42f-0706-4ad0-b127-24078731fbed/project/af137b96-6966-46c1-826b-2e79ac49bbd9",
  "importingUser": {
    "id": "e713cf94-bb02-4ea0-89d9-613cce0caed2",
    "name": "example-user@snyk.io",
    "username": "exampleUser",
    "email": "example-user@snyk.io"
  },
  "isMonitored": false,
  "branch": null,
  "tags": [
    {
      "key": "example-tag-key",
      "value": "example-tag-value"
    }
  ],
  "attributes": {
    "criticality": [
      "high"
    ],
    "environment": [
      "backend"
    ],
    "lifecycle": [
      "development"
    ]
  },
  "remediation": {
    "upgrade": {},
    "patch": {},
    "pin": {}
  }
}
}

const fakeIssue = {
  "id": "npm:ms:20170412",
  "issueType": "vuln",
  "pkgName": "ms",
  "pkgVersions": [
    "1.0.0"
  ],
  "issueData": {
    "id": "npm:ms:20170412",
    "title": "Regular Expression Denial of Service (ReDoS)",
    "severity": "low",
    "url": "https://snyk.io/vuln/npm:ms:20170412",
    "description": "Lorem ipsum",
    "identifiers": {
      "CVE": [],
      "CWE": [
        "CWE-400"
      ],
      "ALTERNATIVE": [
        "SNYK-JS-MS-10509"
      ]
    },
    "credit": [
      "Snyk Security Research Team"
    ],
    "exploitMaturity": "no-known-exploit",
    "semver": {
      "vulnerable": [
        ">=0.7.1 <2.0.0"
      ]
    },
    "publicationTime": "2017-05-15T06:02:45Z",
    "disclosureTime": "2017-04-11T21:00:00Z",
    "CVSSv3": "CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:N/A:L",
    "cvssScore": 3.7,
    "language": "js",
    "patches": [
      {
        "id": "patch:npm:ms:20170412:2",
        "urls": [
          "https://snyk-patches.s3.amazonaws.com/npm/ms/20170412/ms_071.patch"
        ],
        "version": "=0.7.1",
        "comments": [],
        "modificationTime": "2019-12-03T11:40:45.866206Z"
      }
    ],
    "nearestFixedInVersion": "2.0.0"
  },
  "isPatched": false,
  "isIgnored": false,
  "fixInfo": {
    "isUpgradable": false,
    "isPinnable": false,
    "isPatchable": true,
    "nearestFixedInVersion": "2.0.0"
  },
  "priority": {
    "score": 399,
    "factors": [
      {
        "name": "isFixable",
        "description": "Has a fix available"
      },
      {
        "name": "cvssScore",
        "description": "CVSS 3.7"
      }
    ]
  }
}

const fakeResponse = {
  "project": fakeProject,
  "newIssues": [
    fakeIssue,
  ]
}



//////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
import ForgeUI, {
  render,
  Fragment,
  Text,
  ProjectSettingsPage,
  IssuePanel,
  useProductContext,
  useState } from '@forge/ui';
import api, {fetch, storage, startsWith, route} from '@forge/api';

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
      await console.log('We should probably create Jira issues for the critical issues Snyk reports...');


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
      console.log('mapped', mappedAppConfig);
      const newIssueType = mappedAppConfig[0] ? mappedAppConfig[0].value.issueType : false;
      const severityConditions = mappedAppConfig[0] ? mappedAppConfig[0].value.severityLevels : false;
      console.log('newIssueType: ', newIssueType);
      console.log('severity conditions to create on...: ', severityConditions);

      console.log('')
      console.log('Confirming this project has a Jira project mapping before proceeding...');
      console.log('Mapping status: ', jiraMappingExists);
      console.log('Jira ID: ', matchingJiraProjectId);
      // console.log('appConfigs: ', appConfigs[0].value.mappedSnykProjects);
      console.log('')

      // We'll stop here if there is no mapped Jira project for this event's Snyk project
      // if (typeof mappedAppConfig === 'undefined' || mappedAppConfig.length <= 0) {
      //   console.log('This Snyk project has not been configured within the app settings. Aborting.');
      //   // return false;
      // }

      // ***********
      // * Step 3  * - Prepare an array of objects representing new Jira Issues
      // ***********

      // !!!!!!!
      // @TODO: testing only
      newIssueCount = 1;
      // !!!!!!!

      const newIssueData = [];

      if (newIssueCount > 0) {
        for(let i = 0; i < newIssueCount; i++) {
          // const issueData = body.newIssues[i].issueData; // @TODO TEST - Uncomment it.
          const issueData = fakeResponse.newIssues[i].issueData;

          console.log('');
          console.log('this issue id: ', issueData.id);
          console.log('Is the issue\'s severity in the settings list?: ', severityConditions.includes(issueData.severity))
          console.log('');

          const exists = await issueExistsInJira({snykIssueId: issueData.id});
          const existingIssueIdent = await issueExistsInJira({snykIssueId: issueData.id, returnIssueIfTrue: true});

          // const exists = await issueExistsInJira('snyk');
          console.log('find out if it exists already...', exists);
          console.log('If it does exist, here are the identifiers: ', existingIssueIdent);

          if (!exists) {
            newIssueData.push({snykProject: snykProjectName,
                               snykIssueId: issueData.id,
                               snykIssueTitle: issueData.title,
                               snykDescription: issueData.description,
                               snykSeverity: issueData.severity,
                               snykUrl: issueData.url,
                               jiraProjectId: matchingJiraProjectId,
                               jiraIssueTypeId: newIssueType}); // @TODO: Create an option for this on the settings page.
            }
          }
      }

      console.log('Okay, new issues have been cleaned up a bit and put into a new array: ', newIssueData);


      // ***********
      // * Step 4  * - Create new issues in Jira
      // ***********

      console.log('%%%%%%%%%!!!!!!!!%%%%%%%%%%')
      console.log('length of new issue data: ', newIssueData.length);
      if (newIssueData.length > 0) {
        // Here we go...
        console.log('Here we go');
        newIssueData.map(issue => {
          const preparedIssue = prepareNewIssue(issue);
          console.log('preparedIssue: ', preparedIssue);
          createJiraIssue({data: preparedIssue});
            // .then(response => console.log(`Created a new issue in Jira.`))
            // .catch(err => console.log(`There was an error using createJiraIssue(): ${err}`));
        });
      }
      console.log('%%%%%%%%%!!!!!!!!%%%%%%%%%%')

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

// Gets the current Jira instance
// This is primarily useful for creating and searching for issues.
//  - @see: https://community.developer.atlassian.com/t/how-to-retrieve-the-actual-jira-instance-i-am-in/43935/6
export const getJiraEnvironmentId = async () => {
  let result;
  // NOTE/KLUDGE: We have no proper approach for Confluence so far, but can currently rely on a Confluence instance always having a
  // corresponding Jira instance, hence using the respective Jira pproach only for starters:
  //const hostProduct = getHostProduct();
  const hostProduct = "jira";
  if (hostProduct === "jira") {
    result = await api
      .asApp()
      .requestJira("/rest/api/3/serverInfo");
    const serverInfo = await result.json();
    result = serverInfo.id;
  }
  console.log(`Jira instance base: ${result}`);

  return result;
}

// Iterate the issues response object(s):
// - create a corresponding Jira issue if there is no existing Jira issue
//   and the issue is in response.newIssues
// - remove a Jira issue if the issue is in response.removedIssues
// - Do nothing if the issue is in the issues list, but not in new issues
//   AND an existing Jira issue already exists.
const processResponseIssues = () => {};

// Return an object with issue key and ID if there's already a Jira Issue opened
// for a given Snyk issue.
//
// For now, we'll use Jira issue labels to keep track of our issues.
// This is very not ideal.
const issueExistsInJira = async({snykIssueId, returnIssueIfTrue = false} : {string, boolean}) => {
  // Construct the label to look up.
  // The format comes from prepareNewIssue().

  const issueLabel = `snykId-${snykIssueId}`;
  // @TODO: Uncomment this after tests.
  const searchResult = await findJiraIssue(issueLabel);

  console.log(`Here is the search result ${searchResult}`);

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

  // const searchResult = await findJiraIssue(snykIssueId);
  // return searchResult;
};

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
  // .then(text => {
  //   return text
  // })
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
  console.log(`snykDescription - ${snykDescription}`);
  console.log(`snykSeverity - ${snykSeverity}`);
  console.log(`snykUrl - ${snykUrl}`);
  console.log(`jiraProjectId - ${jiraProjectId}`);
  console.log(`jiraIssueType - ${jiraIssueTypeId}`);
  console.log('==========================================');


  // Body data needs to return a _string_ of JSON.
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
      description: {
        type: 'doc',
        version: 1,
        content: [
          {
            type: 'paragraph',
            content: [
              {
                'text': snykDescription + '\n' + snykUrl,
                'type': 'text'
              }
            ]
          }
        ]
      },
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
  console.log('createJiraIssue called. Here inside that function, we\'re about to create an issue.');
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
  console.log('Result: ', result);

  return result;

  // const response = api.asApp().requestJira(
  //   headers: {
  //     'Accept': 'application/json',
  //     'Content-Type': 'application/json'
  //   },
  //   body: JSON.stringify(data)
  // })
  //                     .then(createIssueRes => {
  //                       return createIssueRes.json();
  //                     })
  //                     .catch(err => console.error(`createJiraIssue's API query encountered an error: ${err}`));
  // const output = await response;
  // return output;
}


//   return data;
// };

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

const App = () => {

  useState(getEnvironmentBaseUrl);
  return (
    <Fragment>
      <Text>This is where App config should go</Text>
    </Fragment>
  );
};

export const run = render(
  <ProjectSettingsPage>
    <App />
  </ProjectSettingsPage>
);
