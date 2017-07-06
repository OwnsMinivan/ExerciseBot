import urllib2
import json
import logging
import datetime
import dateutil.parser

import boto3
from boto3.dynamodb.conditions import Key, Attr

dynamodb = boto3.resource('dynamodb')
table = dynamodb.Table('Workout_Checkin_DB')


logger = logging.getLogger()
logger.setLevel(logging.DEBUG)


# --- Helpers that build all of the responses ---

def elicit_slot(session_attributes, intent_name, slots, slot_to_elicit, message):
    return {
        'sessionAttributes': session_attributes,
        'dialogAction': {
            'type': 'ElicitSlot',
            'intentName': intent_name,
            'slots': slots,
            'slotToElicit': slot_to_elicit,
            'message': message
        }
    }


def confirm_intent(session_attributes, intent_name, slots, message):
    return {
        'sessionAttributes': session_attributes,
        'dialogAction': {
            'type': 'ConfirmIntent',
            'intentName': intent_name,
            'slots': slots,
            'message': message
        }
    }


def close(session_attributes, fulfillment_state, message):
    response = {
        'sessionAttributes': session_attributes,
        'dialogAction': {
            'type': 'Close',
            'fulfillmentState': fulfillment_state,
            'message': message
        }
    }

    return response


def delegate(session_attributes, slots):
    return {
        'sessionAttributes': session_attributes,
        'dialogAction': {
            'type': 'Delegate',
            'slots': slots
        }
    }

# --- Helper Functions ---

def build_validation_result(isvalid, violated_slot, message_content):
    return {
        'isValid': isvalid,
        'violatedSlot': violated_slot,
        'message': {'contentType': 'PlainText', 'content': message_content}
    }

def isvalid_date(date):
    try:
        dateutil.parser.parse(date)
        return True
    except ValueError:
        return False

def isvalid_workout(exercise):
    valid_exercises = ['cardio', 'upper', 'lower', 'resistance', 'insanity', 'turbo fire', 'hard corps',
                        'twenty one day fix']
    return exercise.lower() in valid_exercises

def isvalid_mood(mood):
    mood_types = ['hard', 'easy', 'the worst', 'the best']
    return mood.lower() in mood_types

def safe_int(n):
    """
    Safely convert n value to int.
    """
    if n is not None:
        return int(n)
    return n

def try_ex(func):
    """
    Call passed in function in try block. If KeyError is encountered return None.
    This function is intended to be used to safely access dictionary.

    Note that this function would have negative impact on performance.
    """

    try:
        return func()
    except KeyError:
        return None

def generate_checkin_log(exercise, checkin_date, mood, user_id):
    """
    Put the info into a DynamoDB
    """
    response = table.put_item(
        Item={
            'checkin_date': checkin_date,
            'Exercise': exercise,
            'Mood': mood,
            'UserId': user_id
        }
    )
    return response

def validate_workout(slots):
    exercise = try_ex(lambda: slots['WorkoutType'])
    checkin_date = try_ex(lambda: slots['Date'])
    mood = try_ex(lambda: slots['Mood'])

    if exercise and not isvalid_workout(exercise):
        return build_validation_result(
            False,
            'WorkoutType',
            'I have never heard of {} as a valid workout.  Can you try a different workout?'.format(exercise)
        )

    if checkin_date:
        if not isvalid_date(checkin_date):
            return build_validation_result(False, 'Date', 'I did not understand your check in date.  When did you workout?')

        if dateutil.parser.parse(checkin_date) > datetime.datetime.today():
            return build_validation_result(False, 'Date', 'Your check in date is in the future!  Nice try, can you try a different date?')

    if mood and not isvalid_mood(mood):
        return build_validation_result(False, 'Mood', 'I did not recognize how that workout went for you.  Was it easy, hard or the worst?')

    return {'isValid': True}


""" --- Functions that control the bot's behavior --- """

def workout_CheckIn(intent_request):
    """
    Performs dialog management and fulfillment for booking a hotel.

    Beyond fulfillment, the implementation for this intent demonstrates the following:
    1) Use of elicitSlot in slot validation and re-prompting
    2) Use of sessionAttributes to pass information that can be used to guide conversation
    """
    logger.debug('workout_CheckIn slots={}'.format(intent_request['currentIntent']['slots']))

    exercise = try_ex(lambda: intent_request['currentIntent']['slots']['WorkoutType'])
    checkin_date = try_ex(lambda: intent_request['currentIntent']['slots']['Date'])
    mood = try_ex(lambda: intent_request['currentIntent']['slots']['Mood'])
    user_id = try_ex(lambda: intent_request['userId'])

    if intent_request['sessionAttributes']:
        session_attributes = intent_request['sessionAttributes']
    else:
        session_attributes = {}

    # Load workout history and track the current workout.
    overview = json.dumps({
        'RequestType': 'Workout Checkin',
        'Exercise': exercise,
        'Mood': mood,
        'CheckInDate': checkin_date,
        'UserId': user_id
    })
    logger.debug('workout_CheckIn overview={}'.format(overview))
    logger.debug('workout_CheckIn session_attributes={}'.format(session_attributes))
    logger.debug('workout_CheckIn sessionAttributes={}'.format(intent_request['sessionAttributes']))
    session_attributes['currentWorkout'] = overview

    if intent_request['invocationSource'] == 'DialogCodeHook':
        # Validate any slots which have been specified.  If any are invalid, re-elicit for their value
        validation_result = validate_workout(intent_request['currentIntent']['slots'])
        if not validation_result['isValid']:
            slots = intent_request['currentIntent']['slots']
            slots[validation_result['violatedSlot']] = None

            return elicit_slot(
                session_attributes,
                intent_request['currentIntent']['name'],
                slots,
                validation_result['violatedSlot'],
                validation_result['message']
            )

        # Otherwise, let native DM rules determine how to elicit for slots and prompt for confirmation.  Pass price
        # back in sessionAttributes once it can be calculated; otherwise clear any setting from sessionAttributes.
        if exercise and checkin_date and mood and user_id:
            # Save all data into the DynamoDB
            entry_result = generate_checkin_log(exercise, checkin_date, mood, user_id)
            session_attributes['currentCheckinStatus'] = entry_result['ResponseMetadata']['HTTPStatusCode']
        else:
            try_ex(lambda: session_attributes.pop('currentCheckinStatus'))

        session_attributes['currentWorkout'] = overview
        return delegate(session_attributes, intent_request['currentIntent']['slots'])

    # Booking the hotel.  In a real application, this would likely involve a call to a backend service.
    logger.debug('workoutCheckin under={}'.format(overview))

    try_ex(lambda: session_attributes.pop('currentCheckinStatus'))
    try_ex(lambda: session_attributes.pop('currentWorkout'))
    session_attributes['lastConfirmedCheckin'] = overview

    return close(
        session_attributes,
        'Fulfilled',
        {
            'contentType': 'PlainText',
            'content': 'Thanks, I have recorded your workout checkin.'
        }
    )

# --- Intents ---


def dispatch(intent_request):
    """
    Called when the user specifies an intent for this bot.
    """

    logger.debug('dispatch userId={}, intentName={}'.format(intent_request['userId'], intent_request['currentIntent']['name']))

    intent_name = intent_request['currentIntent']['name']

    # Dispatch to your bot's intent handlers
    if intent_name == 'WorkoutCheckIn':
        return workout_CheckIn(intent_request)
    ##this needs to be modified to remove the example of BookCar
    elif intent_name == 'BookCar':
        return book_car(intent_request)

    raise Exception('Intent with name ' + intent_name + ' not supported')


# --- Main handler ---


def lambda_handler(event, context):
    """
    Route the incoming request based on intent.
    The JSON body of the request is provided in the event slot.
    """

    logger.debug('event.bot.name={}'.format(event['bot']['name']))

    return dispatch(event)
