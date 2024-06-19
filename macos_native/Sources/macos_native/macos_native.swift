import UserNotifications

// Function can return following u8 values:
//   101 - user didn't grant a notification access.
@_cdecl("notify")
public func notify(
  identifierPtr: UnsafePointer<UInt8>, identifierLen: UInt64, titlePtr: UnsafePointer<UInt8>,
  titleLen: UInt64, descriptionPtr: UnsafePointer<UInt8>, descriptionLen: UInt64
) -> UInt8 {
  let center = UNUserNotificationCenter.current()

  let semaphore = DispatchSemaphore(value: 0)

  let grantedQueue = DispatchQueue(label: "grantedQueue")
  var granted: Bool = false
  // Request user authorization to add notification to the center.
  Task {
    do {
      let isGranted = try await center.requestAuthorization(options: [.alert, .sound, .badge])
      grantedQueue.sync {
        granted = isGranted
      }
      semaphore.signal()
    } catch {
      // Error code 1 means user already declined our authorization request.
      if ((error as NSError).code) != 1 {
        print("Failed to request authorization: \(error)")
      }
      semaphore.signal()
    }
  }
  semaphore.wait()
  if !granted {
    return 101
  }

  let identifier = parseParameter(parameterPtr: identifierPtr, parameterLen: identifierLen)
  let title = parseParameter(parameterPtr: titlePtr, parameterLen: titleLen)
  let description = parseParameter(parameterPtr: descriptionPtr, parameterLen: descriptionLen)
  let content = UNMutableNotificationContent()
  content.title = title
  content.body = description
  let notification = UNNotificationRequest(
    identifier: identifier, content: content, trigger: nil)
  Task {
    do {
      try await center.add(notification)
      semaphore.signal()
    } catch {
      print("Failed to add notification to queue: \(error)")
      semaphore.signal()
    }
  }
  semaphore.wait()

  return 0
}

func parseParameter(parameterPtr: UnsafePointer<UInt8>, parameterLen: UInt64) -> String {
  let parameterBuf = UnsafeBufferPointer(start: parameterPtr, count: Int(parameterLen))
  let parameterData = Data(buffer: parameterBuf)
  let parameter = String(data: parameterData, encoding: .utf8)!
  return parameter
}
