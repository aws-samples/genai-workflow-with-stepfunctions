# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0
import json
import re


def lambda_handler(event, context):  # pylint: disable=unused-argument
    # Debug
    print(json.dumps(event))

    # parse gen AI output and extract text content
    output_content_regex = re.compile('<output>((.|\n)*)</output>')
    model_response = event['modelResponse']['content'][0]['text']
    match_group = output_content_regex.search(model_response)
    if not match_group:
        raise ValueError('No <output> tag found in the model response')
    json_content = json.loads(match_group.group(1))

    # create response in dynamodb record format
    response = {
        'RecordId': {
            'S': event.get('recordId')
        },
        'UpdatedTime': {
            'S': event.get('updatedTime')
        }
    }

    for key, value in json_content.items():
        response[key] = {'S': value}

    return response
