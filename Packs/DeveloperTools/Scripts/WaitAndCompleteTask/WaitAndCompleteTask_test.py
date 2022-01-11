import pytest

from WaitAndCompleteTask import wait_and_complete_task_command

TASK_BY_STATES = [
    {
        'name': 'conditional task 1',
        'id': 1,
        'parentPlaybookID': 123,
        'state': 'Waiting'
    },
    {
        'name': 'conditional task 2',
        'id': 2,
        'parentPlaybookID': 123,
        'state': 'Waiting'
    },
    {
        'name': 'manual task 1',
        'id': 3,
        'parentPlaybookID': 123,
        'state': 'Waiting'
    },
    {
        'name': 'manual task 2',
        'id': 4,
        'parentPlaybookID': 123,
        'state': 'Waiting'
    }
]

COMPLETE_RES_ALREADY_COMPLETED = 'Task is completed already'
COMPLETE_RES = '{"id": some_id}'


@pytest.mark.parametrize('args,tasks_ret_value,complete_res,completed_tasks,found_tasks', [
    ({'incident_id': 1,
      'task_states': 'Waiting',
      'complete_option': 'yes',
      'task_name': 'conditional task 1',
      'complete_task': 'true',
      'max_iterations': '1'
      },
     TASK_BY_STATES, COMPLETE_RES, ['conditional task 1'], []),
    ({'incident_id': 1,
      'task_states': 'Waiting',
      'task_name': 'conditional task 1',
      'max_iterations': '1',
      'complete_task': 'false',
      },
     TASK_BY_STATES, COMPLETE_RES, [], ['conditional task 1']),
    ({'incident_id': 1,
      'task_states': 'Waiting',
      'max_iterations': '1',
      'complete_task': 'true',
      },
     TASK_BY_STATES, COMPLETE_RES, ['conditional task 1', 'conditional task 2', 'manual task 1', 'manual task 2'],
     []),
    ({'incident_id': 1,
      'task_states': 'Waiting',
      'max_iterations': '1',
      'complete_task': 'true',
      },
     TASK_BY_STATES, COMPLETE_RES_ALREADY_COMPLETED, [],
     ['conditional task 1', 'conditional task 2', 'manual task 1', 'manual task 2']),
    ({'incident_id': 1,
      'task_states': 'Waiting',
      'max_iterations': '1',
      'complete_task': 'false',
      },
     TASK_BY_STATES, '', [],
     ['conditional task 1', 'conditional task 2', 'manual task 1', 'manual task 2'])
])
def test_wait_and_complete_task_command(mocker, args, tasks_ret_value, complete_res, completed_tasks, found_tasks):
    """
    Given:
        - The "WaitAndCompleteTask" script

    When:
        - Waiting to all task that has given status

    Then:
        - Validate the output returned as expected

    """
    mocker.patch('WaitAndCompleteTask.get_incident_tasks_by_state', return_value=tasks_ret_value)
    mocker.patch('WaitAndCompleteTask.complete_task_by_id', return_value=complete_res)
    response = wait_and_complete_task_command(args)

    assert response.outputs == {'CompletedTask': completed_tasks,
                                'FoundTasks': found_tasks}


@pytest.mark.parametrize('args,res', [
    ({'incident_id': 1,
      'task_states': 'Waiting',
      'task_name': 'conditional task 1',
      'sleep_time': '1',
      'max_timeout': '1'
      },
     'The task "conditional task 1" did not reach the Waiting state'
     ),
    ({'incident_id': 1,
      'task_name': 'conditional task 1',
      'sleep_time': '1',
      'max_timeout': '1'
      },
     'The task "conditional task 1" was not found by script'
     ),
    ({'incident_id': 1,
      'task_states': 'Waiting,Completed',
      'sleep_time': '1',
      'max_timeout': '1'
      },
     'None of the tasks reached the Waiting or Completed'
     ),
    ({'incident_id': 1,
      'sleep_time': '1',
      'max_timeout': '1'
      },
     'No tasks were found'
     )
])
def test_wait_and_complete_task_command_failure(mocker, args, res):
    """
    Given:
        - The "WaitAndCompleteTask" script

    When:
        - Waiting to all task that has given status

    Then:
        - Validate the output returned as expected

    """
    mocker.patch('WaitAndCompleteTask.get_incident_tasks_by_state', return_value=[])
    error = ''
    try:
        wait_and_complete_task_command(args)
    except Exception as e:
        error = str(e)

    assert res in error
