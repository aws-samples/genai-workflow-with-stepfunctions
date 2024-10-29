# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0
import json


def lambda_handler(event, context):  # pylint: disable=unused-argument
    print(event)

    rows = event.get('Rows')

    response = {}

    if rows and len(rows) == 2:
        for i in range(0, len(rows[0]['Data'])):
            response[rows[0]['Data'][i]['VarCharValue']
                     ] = rows[1]['Data'][i]['VarCharValue']

    return json.dumps(response, indent=2)
