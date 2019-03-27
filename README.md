# gosig
An interface for wrapping different digital signature implementations

The interface generally tries to be stateless. The output of the sign method is a buffer thats encoded based on each implementation. This is useful for using different digital signatures schemes in a pluggable way. 
