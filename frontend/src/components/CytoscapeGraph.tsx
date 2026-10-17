import React, { useEffect, useRef } from 'react';
import cytoscape, { Core } from 'cytoscape';
import { CytoscapeElement } from '../types';
import { ZoomIn, ZoomOut, Maximize2 } from 'lucide-react';

interface Props {
  elements: CytoscapeElement[];
  onSelectNode: (nodeData: any) => void;
  selectedNodeId?: string;
}

export const CytoscapeGraph: React.FC<Props> = ({ elements, onSelectNode, selectedNodeId }) => {
  const containerRef = useRef<HTMLDivElement>(null);
  const cyRef = useRef<Core | null>(null);

  useEffect(() => {
    if (!containerRef.current) return;

    // Initialize Cytoscape
    const cy = cytoscape({
      container: containerRef.current,
      elements: elements as any,
      style: [
        {
          selector: 'node',
          style: {
            'label': 'data(label)',
            'color': '#F3F4F6',
            'font-size': '11px',
            'font-family': 'JetBrains Mono, monospace',
            'text-valign': 'bottom',
            'text-margin-y': 6,
            'background-color': '#374151',
            'border-width': 2,
            'border-color': '#1F2937',
            'width': 36,
            'height': 36,
            'text-background-opacity': 0.8,
            'text-background-color': '#111827',
            'text-background-padding': '2px',
            'text-background-shape': 'roundrectangle',
          },
        },
        // Node Type Styling
        {
          selector: 'node[type = "process"]',
          style: {
            'background-color': '#06B6D4',
            'border-color': '#22D3EE',
            'shape': 'roundrectangle',
          },
        },
        {
          selector: 'node[type = "account"]',
          style: {
            'background-color': '#8B5CF6',
            'border-color': '#A78BFA',
            'shape': 'ellipse',
          },
        },
        {
          selector: 'node[type = "network_endpoint"]',
          style: {
            'background-color': '#F59E0B',
            'border-color': '#FBBF24',
            'shape': 'diamond',
            'width': 40,
            'height': 40,
          },
        },
        {
          selector: 'node[type = "evidence"]',
          style: {
            'background-color': '#10B981',
            'border-color': '#34D399',
            'shape': 'hexagon',
          },
        },
        {
          selector: 'node[type = "mitre_assessment"]',
          style: {
            'background-color': '#EF4444',
            'border-color': '#F87171',
            'shape': 'round-tag',
          },
        },
        {
          selector: 'node[type = "limitation"]',
          style: {
            'background-color': '#4B5563',
            'border-color': '#6B7280',
            'shape': 'rectangle',
            'width': 28,
            'height': 28,
          },
        },
        // Selected Node Highlight
        {
          selector: 'node:selected',
          style: {
            'border-color': '#FFFFFF',
            'border-width': 4,
          },
        },
        // Edge Styling
        {
          selector: 'edge',
          style: {
            'label': 'data(label)',
            'font-size': '9px',
            'color': '#9CA3AF',
            'font-family': 'JetBrains Mono, monospace',
            'text-rotation': 'autorotate',
            'text-margin-y': -8,
            'width': 2,
            'line-color': '#374151',
            'target-arrow-color': '#4B5563',
            'target-arrow-shape': 'triangle',
            'curve-style': 'bezier',
            'arrow-scale': 1.2,
          },
        },
        {
          selector: 'edge[type = "process_spawn"]',
          style: {
            'line-color': '#06B6D4',
            'target-arrow-color': '#06B6D4',
            'width': 2.5,
          },
        },
        {
          selector: 'edge[type = "supports_assessment"]',
          style: {
            'line-color': '#EF4444',
            'target-arrow-color': '#EF4444',
            'line-style': 'dashed',
          },
        },
      ],
      layout: {
        name: 'cose',
        animate: true,
        animationDuration: 500,
        nodeRepulsion: () => 400000,
        nodeOverlap: 20,
        idealEdgeLength: () => 100,
        edgeElasticity: () => 100,
        padding: 40,
      },
    });

    cy.on('tap', 'node', (evt) => {
      const node = evt.target;
      onSelectNode(node.data());
    });

    cyRef.current = cy;

    return () => {
      cy.destroy();
    };
  }, [elements]);

  // Sync selected node
  useEffect(() => {
    if (!cyRef.current) return;
    cyRef.current.nodes().unselect();
    if (selectedNodeId) {
      cyRef.current.$id(selectedNodeId).select();
    }
  }, [selectedNodeId]);

  const handleZoomIn = () => cyRef.current?.zoom(cyRef.current.zoom() * 1.2);
  const handleZoomOut = () => cyRef.current?.zoom(cyRef.current.zoom() / 1.2);
  const handleFit = () => cyRef.current?.fit(undefined, 30);

  return (
    <div className="relative w-full h-full bg-[#080C14] border border-soc-border rounded-lg overflow-hidden">
      <div ref={containerRef} className="w-full h-full" />
      
      {/* Control Buttons */}
      <div className="absolute bottom-4 right-4 flex flex-col gap-2 bg-soc-card/80 backdrop-blur border border-soc-border rounded-md p-1 shadow-lg">
        <button
          onClick={handleZoomIn}
          className="p-1.5 text-soc-muted hover:text-white hover:bg-gray-700/50 rounded transition"
          title="Zoom In"
        >
          <ZoomIn className="w-4 h-4" />
        </button>
        <button
          onClick={handleZoomOut}
          className="p-1.5 text-soc-muted hover:text-white hover:bg-gray-700/50 rounded transition"
          title="Zoom Out"
        >
          <ZoomOut className="w-4 h-4" />
        </button>
        <button
          onClick={handleFit}
          className="p-1.5 text-soc-muted hover:text-white hover:bg-gray-700/50 rounded transition"
          title="Fit View"
        >
          <Maximize2 className="w-4 h-4" />
        </button>
      </div>

      {/* Legend */}
      <div className="absolute top-4 left-4 bg-soc-card/90 backdrop-blur border border-soc-border rounded-md px-3 py-2 text-xs flex gap-4 shadow-lg pointer-events-none">
        <div className="flex items-center gap-1.5">
          <span className="w-2.5 h-2.5 rounded-sm bg-[#06B6D4]" />
          <span>Process</span>
        </div>
        <div className="flex items-center gap-1.5">
          <span className="w-2.5 h-2.5 rounded-full bg-[#8B5CF6]" />
          <span>Account</span>
        </div>
        <div className="flex items-center gap-1.5">
          <span className="w-2.5 h-2.5 rotate-45 bg-[#F59E0B]" />
          <span>Endpoint</span>
        </div>
        <div className="flex items-center gap-1.5">
          <span className="w-2.5 h-2.5 rounded-sm bg-[#10B981]" />
          <span>Evidence</span>
        </div>
        <div className="flex items-center gap-1.5">
          <span className="w-2.5 h-2.5 rounded-sm bg-[#EF4444]" />
          <span>MITRE</span>
        </div>
      </div>
    </div>
  );
};
