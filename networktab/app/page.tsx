'use client'

import { useEffect, useState } from "react";

type Request = {
  method: string;
  url: string;
  host: string;
  content_type: string;
};

function path(r: Request): string {
  let u = new URL(r.url);
  return u.pathname;
}

type Response = {
  status: string;
  size: number;
};

type Call = {
  request: Request;
  response: Response;
  total_bytes: number;
};

export type Calls = Call[];

function Row(props) {
  const call: Call = props.call;
  const selected: boolean = props.selected;
  const onClick = props.onClick;

  return (
    <tr onClick={onClick} className={selected ? "selected": ""}>
      <td>{call.response.status}</td>
      <td>{call.request.method}</td>
      <td>{call.request.host}</td>
      <td>{path(call.request)}</td>
      <td>{call.request.content_type}</td>
      <td>{call.total_bytes}</td>
      <td>{call.response.size}</td>
    </tr>
  )
}

export default function Home() {
  const [calls, setCalls] = useState<Calls>([]);
  const [selectedIndex, setSelectedIndex] = useState<number>(-1);

  function selectRow(e: MouseEvent, index: number) {
    e.preventDefault();
    setSelectedIndex(index);
  }

  // useEffect means react will run the inner function once whenever the listed dependencies change
  useEffect(() => {
    const stream = new EventSource('/api/calls');
    stream.onmessage = (event) => {
      const payload: Call = JSON.parse(event.data);
      setCalls((calls) => [...calls, payload]);
    };
    stream.onerror = (err) => {
      console.error("error reading calls from backend:", err);
    };
    return () => {
      console.log("closing event source");
      stream.close();
    };
  }, []);

  return (
    <main>
      <menu>
        <button className="selected">All</button>
        <button>JSON</button>
        <button>XML</button>
        <button>HTML</button>
        <button>CSS</button>
        <button>JS</button>
        <button>Images</button>
        <button>WS</button>
        <button>Other</button>
      </menu>
      <table>
        <thead>
          <tr>
            <td>Status</td>
            <td>Method</td>
            <td>Domain</td>
            <td>File</td>
            <td>Type</td>
            <td>Transferred</td>
            <td>Size</td>
          </tr>
        </thead>
        <tbody>
          {calls.map((call, index) => (
            <Row key={index} call={call} selected={index == selectedIndex} onClick={(e: MouseEvent) => selectRow(e, index)} />
          ))}
        </tbody>
      </table>
    </main>
  );
}
