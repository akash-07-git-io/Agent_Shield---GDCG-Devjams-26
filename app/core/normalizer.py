from datetime import datetime, timezone
import re
from typing import Any, Dict, Optional, Union
from app.models.action import NormalizedAction, RawToolCall

class ActionNormalizer:
    """
    Normalizes diverse tool calls and raw agent payloads into canonical NormalizedAction structures.
    """

    ACTION_MAP = {
        'read_logs': 'read',
        'read_file': 'read',
        'view_file': 'read',
        'search_repo': 'search',
        'list_dir': 'list',
        'send_email': 'send',
        'upload_file': 'upload',
        'write_file': 'write',
        'db_query': 'query',
        'execute_command': 'execute',
        'run_command': 'execute',
        'http_request': 'send',
        'delete_file': 'delete',
        'grant_permission': 'modify_iam',
        'sudo_exec': 'escalate_privilege',
    }

    RESOURCE_KEYS = ['resource', 'file', 'path', 'filepath', 'filename', 'table', 'target', 'query', 'url', 'cmd', 'command']
    DESTINATION_KEYS = ['destination', 'to', 'recipient', 'host', 'endpoint', 'email', 'url', 'target_url']

    @classmethod
    def normalize(cls, data: Union[RawToolCall, NormalizedAction, Dict[str, Any]]) -> NormalizedAction:
        if isinstance(data, NormalizedAction):
            return data

        if isinstance(data, RawToolCall):
            raw = data.model_dump()
        elif isinstance(data, dict):
            raw = data
        else:
            raise ValueError(f"Unsupported action format: {type(data)}")

        tool_name = raw.get('tool_name') or raw.get('tool') or 'unknown_tool'
        args = raw.get('arguments') or raw.get('payload') or {}
        agent_id = raw.get('agent_id', 'devops-agent-01')
        user_id = raw.get('user_id', 'developer-01')
        context = raw.get('context') or 'DevOps Assistant Workflow'
        raw_prompt = raw.get('raw_prompt')

        # Deducing action verb
        explicit_action = raw.get('action') or args.get('action')
        if explicit_action:
            action = str(explicit_action).lower()
        else:
            action = cls.ACTION_MAP.get(tool_name.lower(), 'execute')

        # Refine action if db query contains write keywords
        if tool_name == 'db_query' or 'db' in tool_name:
            query_str = str(args.get('query', '')).lower()
            if any(k in query_str for k in ['insert', 'update', 'delete', 'drop', 'alter', 'truncate', 'write']):
                action = 'write'
            else:
                action = 'read'

        # Finding resource
        resource = raw.get('resource') or args.get('resource')
        if not resource:
            for k in cls.RESOURCE_KEYS:
                if k in args and args[k]:
                    resource = str(args[k])
                    break
        if not resource:
            resource = tool_name

        # Finding destination
        destination = raw.get('destination') or args.get('destination')
        if not destination:
            for k in cls.DESTINATION_KEYS:
                if k in args and args[k]:
                    destination = str(args[k])
                    break

        # Check for embedded prompt in payload or args
        if not raw_prompt:
            for k in ['prompt', 'input', 'instruction', 'body', 'content', 'query']:
                if k in args and isinstance(args[k], str):
                    raw_prompt = args[k]
                    break

        return NormalizedAction(
            agent_id=agent_id,
            user_id=user_id,
            tool=tool_name,
            action=action,
            resource=resource,
            destination=destination,
            context=context,
            payload=args,
            raw_prompt=raw_prompt,
            timestamp=datetime.now(timezone.utc)
        )
