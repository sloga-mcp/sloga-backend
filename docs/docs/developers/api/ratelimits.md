# Rate Limits

Acutest uses a fixed-window ratelimiting algorithm:

- You are given a set amount of calls per each named bucket.
- Any calls past this limit will result in 429 errors.
- Buckets are replenished after 10 seconds from initial request.

## Buckets

There are distinct buckets that you may be calling against, none of these affect each other and can be used up independently of one another.

|   Method | Path                        | Limit |
| -------: | --------------------------- | :---: |
|          | `/users`                    |  20   |
|  `PATCH` | `/users/:id`                |   2   |
|          | `/users/:id/default_avatar` |  255  |
|          | `/bots`                     |  10   |
|          | `/bots/:id/commands`        |  10   |
|          | `/channels`                 |  15   |
|   `POST` | `/channels/:id/messages`    |  10   |
|   `POST` | `/channels/:id/interactions` |  10   |
|   `POST` | `/channels/:id/interactions/autocomplete` |  40   |
|   `POST` | `/channels/:id/messages/:id/interact` |  20   |
|          | `/interactions/:id/respond` |  30   |
|          | `/interactions/:id/autocomplete` |  40   |
|          | `/servers`                  |   5   |
|          | `/auth`                     |   3   |
| `DELETE` | `/auth`                     |  255  |
|          | `/safety`                   |  15   |
|          | `/safety/report`            |   3   |
|          | `/swagger`                  |  100  |
|          | `/*`                        |  20   |

## Headers

There are multiple headers you can use to figure out when you can and cannot send requests, and to determine when you can next send a request.

| Header                    |   Type   | Description                                      |
| ------------------------- | :------: | ------------------------------------------------ |
| `X-RateLimit-Limit`       | `number` | Maximum number of calls allowed for this bucket. |
| `X-RateLimit-Bucket`      | `string` | Unique identifier for this bucket.               |
| `X-RateLimit-Remaining`   | `number` | Remaining number of calls left for this bucket.  |
| `X-RateLimit-Reset-After` | `number` | Milliseconds left until calls are replenished.   |

## Rate Limited Response

When you receive `429 Too Many Requests`, read `X-RateLimit-Reset-After` to find out how long to wait. It is present on every response, including the 429 itself.

**Do not rely on the response body.** The main API sends the wait in the headers only; the body of a 429 is not part of the contract and should not be parsed. The file upload service does return a JSON body alongside the headers:

```typescript
interface Response {
  // Milliseconds until calls are replenished
  retry_after: number;
}
```
