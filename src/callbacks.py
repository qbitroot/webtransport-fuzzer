
import logging

logger = logging.getLogger(__name__)

def callback_fill_session_id(target, fuzz_data_logger, session, node, edge, *args, **kwargs):
    """
    Callback to update the 'SessionID' field in the current message 
    with the actual session ID from the target connection.
    """
    try:
        conn = target._target_connection
        if not conn:
            return

        session_id = conn.session_id
        if session_id is None:
            # Not yet connected or established
            return

        # Find the SessionID field in the current node's request
        # Boofuzz nodes contain 'items' which are the primitives.
        # We need to find the one named "SessionID".
        
        # Note: 'node' here is the Request (s_get object structure).
        # We can iterate over node.stack (if exposed) or names.
        
        # However, Boofuzz callbacks usually modify the graph or logs.
        # Modifying the *values* of primitives just before send is tricky 
        # because mutations might already be generated.
        
        # ACTUALLY: The standard way in Boofuzz to have dynamic data 
        # is to use a block that takes a function or update the context.
        # But 's_bytes' is static.
        
        # Strategy: We can't easily change the *definition* on the fly for mutations 
        # if the mutator has already calculated them.
        # BUT: For the 'SessionID' field, we don't really want to fuzz it 
        # with random data usually, or if we do, we want the *base* to be correct.
        
        # ALTERNATIVE: The `connection.send` patching IS actually a common pattern 
        # for session IDs in Boofuzz because the ID is often not known until runtime.
        session_id_primitive = None
        # Boofuzz names are fully qualified (e.g. "node_name.SessionID")
        for name, primitive in node.names.items():
            if name.endswith(".SessionID") or name == "SessionID":
                session_id_primitive = primitive
                break
        
        if session_id_primitive:
            # Update the primitive's value
            if session_id < 64:
                # Update both _value and _opt_value and default to be safe
                session_id_primitive._value = bytes([session_id])
                session_id_primitive._default_value = bytes([session_id])
                
                # Clear the primitive's cache (this is critical for Boofuzz to re-render)
                if hasattr(session_id_primitive, '_rendered'):
                    session_id_primitive._rendered = None
                
                logger.debug(f"Updated SessionID primitive to {session_id} and cleared cache")
        else:
            logger.debug(f"SessionID primitive not found in node names: {list(node.names.keys())}")
                
    except Exception as e:
        logger.error(f"Callback failed: {e}")
